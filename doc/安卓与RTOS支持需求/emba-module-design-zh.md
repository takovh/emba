# EMBA扫描固件生成SBOM模块 — 概要设计

## 1. 概述

以 [EMBA](https://github.com/e-m-b-a/emba) 作为固件解包与静态分析引擎，扫描固件/二进制制品生成 CycloneDX SBOM；对 EMBA 原生不覆盖的 Android APK 组件识别，通过自定义 S08 子模块集成 **Blint**（[OWASP dep-scan](https://github.com/owasp-dep-scan/blint) 维护）实现；RTOS 与 SDK 制品通过EMBA现有功能实现。产出的 SBOM 经后处理与校验后入库、同步至 ODT（Dependency-Track）用于漏洞关联，支撑 CRA / prEN 40000-1-3 的 [PRE-6]（产品识别）、[PRE-7]（软件组件识别）、[PRE-8]（硬件组件识别）条款。

### 1.2 目标与定位

- 扫描固件（Linux、Android、RTOS）与二进制/SDK 制品，生成符合 CRA 要求的 CycloneDX SBOM
- 补齐 EMBA 官方能力缺口：**Android APK 组件识别（Blint实现）**
- 保证 PRE-7 要求的组件三要素（生产商、名称、版本）与唯一标识符（PURL/CPE）落库

最终在平台侧聚合为完整供应链视图：源码侧 SBOM 提供精确应用依赖，EMBA 侧 SBOM 提供固件内实际存在的组件。

### 1.3 总体流程

```
固件上传（分片/异步上传）
   ↓
任务编排（复用平台异步任务管理：排队 / 状态 / 取消）
   ↓
执行 EMBA：sudo ./emba -f <upload> -l <embaLogPath>/<taskId> -p <profile> -y
   ↓
P阶段: 解包与索引
   ├── P25 Android OTA (payload_dumper.py) / P65 包归档提取（含 apk_extractor）
   ├── P50/P55 binwalk / unblob，自定义 YAFFS、Rockchip 等提取器
   └── P99 文件索引 → P99_CSV_LOG（路径、类型、哈希）
   ↓
S阶段: 静态分析（组件识别）
   ├── S06  Linux 发行版识别
   ├── S08  包管理器 SBOM（原生 22 个子模块 + 自定义子模块）
   │        ├── android_apk_metadata（自定义：packages.xml/build.prop/vintf）
   │        └── android_apk_sbom（自定义：调用 Blint）★
   ├── S09  二进制版本检测（覆盖所有平台的 ELF/so）
   └── S24/S25 内核与模块
   ↓
F阶段: 报告生成
   ├── F14 许可证汇总 / F15 CycloneDX 合并 → EMBA_cyclonedx_sbom.json
   └── F17 CVE 聚合（可选，生成 VEX）
```

> EMBA 自定义子模块（shell + blint 调用）随 EMBA 部署目录分发，不属于平台 Java 代码。

## 2. 功能设计

### 2.1 Android 固件扫描设计

#### 2.1.1 技术选型

| 候选                    | 结论                                                                                                                                                                         |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Blint（选用）** | 一条命令输出 CycloneDX；同时覆盖 Manifest、native`.so`、DEX、SDK/追踪器；MIT 许可、活跃维护、与 dep-scan 同生态，后续可直接被 `depscan --bom-engine BlintGenerator` 消费 |
| 自写 Manifest 解析      | 只能拿到包名与版本，无法覆盖 native 库与 SDK；保留为**权威元数据来源**（见 6.5），不作为唯一手段                                                                       |
| AndroGuard / MobSF      | 能力强但偏安全测试（权限、漏洞、加壳），SBOM 输出需自行封装；与既有技术栈整合成本更高                                                                                        |
| jadx / APKiD            | 反编译与加壳识别工具，非组件清单工具                                                                                                                                         |

官方定位补充（OWASP MASTG-TOOL-0130）：由 APK 生成的 SBOM **天然不完整**（库的元信息在打包时已被剥离）。
因此 Blint 的定位是【在 EMBA 既有能力之外，最大化召回 APK 内可识别组件】，而非完整依赖清单；

#### 2.1.2 固件提取

| 场景                      | 方案                                                                                                        |
| ------------------------- | ----------------------------------------------------------------------------------------------------------- |
| OTA 包（`payload.bin`） | EMBA`P25_android_ota` + `payload_dumper.py`                                                             |
| 完整固件（zip/tar）       | 平台侧按包格式预处理：YAFFS、瑞芯微（Rockchip）、海思（zip 直解）等自定义解包脚本（已实现），再交 EMBA 分析 |
| 分区镜像                  | `system.img/vendor.img/product.img` 等经 binwalk/unblob/挂载提取                                          |
| 增量包                    | 需与旧版基线镜像做差分还原后才能扫描                                                                        |

提取后，P65 `apk_extractor` 将 `.apk` 归档还原到文件系统，与 `system/app/`、`vendor/app/` 下的预置 APK 一同进入 `P99_CSV_LOG` 索引，供 S08 子模块定位。

#### 2.1.3 自定义 APK 组件识别模块

`S08_submodule_android_apk_sbom`：APK 文件本体（`AndroidManifest.xml`、`lib/*.so`、`*.dex`、`*.version`）→ **Blint**

自定义子模块与原生子模块遵循相同的三步工作模式（定位 → 解析 → 写入 SBOM），复用 EMBA 共享辅助库：

| 辅助函数                                                    | 作用                                           |
| ----------------------------------------------------------- | ---------------------------------------------- |
| `module_log_init` / `module_title` / `module_end_log` | 模块日志生命周期（`NEG_LOG` 标记是否有产出） |
| `build_sbom_json_hashes_arr`                              | 计算 MD5/SHA-256/SHA-512 并执行去重检查        |
| `build_sbom_json_properties_arr`                          | 构建`EMBA:sbom:*` 属性数组                   |
| `build_sbom_json_component_arr`                           | 序列化并写入`${SBOM_LOG_PATH}/*.json`        |

`S08_submodule_android_apk_sbom.sh`执行流程：

```
1. 定位候选文件
   └── grep -E '\.apk;|\.aab;|\.apks;|\.xapk;|\.apkm;' "${P99_CSV_LOG}" | cut -d ';' -f2

2. 甄别 Android APK 与 Alpine .apk  【关键】
   ├── Alpine apk 归档（tar.gz + .PKGINFO）→ 交由原生 alpine_apk_package_parser，本子模块跳过
   └── Android APK（zip + AndroidManifest.xml）→ 进入步骤 3
       判定：zip 魔数（PK\x03\x04）且 unzip -l 中存在 AndroidManifest.xml
       （两类归档同名 .apk，若不甄别会与原生子模块互相干扰/误报）

3. 逐个执行 Blint（默认开启；失败降级不阻塞）
   blint --no-banner sbom -i <apk> -o ${SBOM_LOG_PATH}/blint/<apk>.cdx.json
   ├── 加超时保护（单 APK 级超时，固定 600 秒）
   └── 断言输出文件存在（Blint 对不存在的输入退出码为 0 且不产出文件）

4. 解析输出（jq）
   ├── metadata.component   → APK 根组件：purl、versionName、minSdk/targetSdk/compileSdk 属性
   ├── components[]         → native so / dex / maven 版本文件等子组件（含 evidence.confidence）
   ├── services[]           → 识别到的 SDK / 追踪器
   └── dependencies[]       → 根 → 子组件依赖边

5. 写入 EMBA SBOM（与原生子模块同构）
   build_sbom_json_hashes_arr → build_sbom_json_properties_arr（追加 gst:blint:* 属性）
                              → build_sbom_json_component_arr

6. module_end_log：有产出置 NEG_LOG=1
```

伪代码（与可行性分析文档的自定义模块风格一致）：

```bash
S08_submodule_android_apk_sbom() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Android APK SBOM generator (blint)"

  local lNEG_LOG=0
  command -v blint >/dev/null 2>&1 || { print_output "[-] blint not available" "no"; module_end_log "${FUNCNAME[0]}" "$lNEG_LOG"; return 0; }

  local lAPK_OUT_DIR="${SBOM_LOG_PATH}/blint"
  mkdir -p "${lAPK_OUT_DIR}"

  while IFS= read -r lAPK; do
    is_android_apk "${lAPK}" || continue          # 排除 Alpine .apk
    local lOUT="${lAPK_OUT_DIR}/$(basename "${lAPK}").cdx.json"

    timeout 600s blint --no-banner sbom -i "${lAPK}" -o "${lOUT}" || true
    [[ -s "${lOUT}" ]] || continue                # Blint 可能退出 0 但无产物

    # 解析并写入 EMBA SBOM（APK 根组件 + 子组件 + services）
    blint_sbom_to_emba_components "${lOUT}" "${lAPK}"
    lNEG_LOG=1
  done < <(grep -E '\.apk;|\.aab;|\.apks;|\.xapk;|\.apkm;' "${P99_CSV_LOG}" | cut -d ';' -f2)

  module_end_log "${FUNCNAME[0]}" "$lNEG_LOG"
}
```

> `is_android_apk` / `blint_sbom_to_emba_components` 为子模块内辅助函数；`build_sbom_json_component_arr` 等辅助函数的**确切签名以所部署 EMBA 版本源码为准**，实现阶段需与 `helpers_emba_sbom_helpers.sh` 对齐。

#### 2.1.4 Blint 输出 → SBOM 组件映射

| Blint 输出                                                    | 目标组件                                      | 置信度    | 处理说明                                                                                                      |
| ------------------------------------------------------------- | --------------------------------------------- | --------- | ------------------------------------------------------------------------------------------------------------- |
| `metadata.component`（`pkg:android/<pkg>@<versionName>`） | APK 根组件（`type=application`，父组件）    | 1.0       | 属性保留`internal:minSdkVersion/targetSdkVersion/compileSdkVersion`；版本为空时降级为 `pkg:android/<pkg>` |
| `components[].purl = pkg:android/<name>?arch=<abi>`         | native 库组件（叶子，参与漏洞匹配）           | 0.5       | 由`lib/**/*.so` 经 LIEF 解析；`version` 取 ELF notes，缺失则置空                                          |
| `components[].purl = pkg:android/classes`（dex）            | DEX 容器组件                                  | 0.2       | 低置信度；默认仅作为 APK 子节点保留，不作为漏洞匹配的叶子依据                                                 |
| `components[].purl = pkg:maven/<g>/<a>@<v>`                 | Java 归档组件                                 | 1.0 / 0.2 | 来自 APK 内`*.version` 文件；`group` 缺失或版本为 `latest` 时降至 0.2                                   |
| `components[].purl = pkg:file/<soname>`                     | 归一化为`pkg:generic/<soname>`              | 0.5       | `pkg:file` 非注册 purl 类型；原值保留于 `gst:blint:raw_purl`                                              |
| `services[]`（SDK/追踪器）                   | 组件属性`gst:blint:service=<name>` 或子组件 | —        | 仅保留实际输出的服务信息；本模块不启用 deep                                                                            |
| `evidence.identity.methods[].technique`                     | 属性`gst:blint:technique=binary-analysis`   | —        | 保留识别技术供审计                                                                                            |
| `metadata.tools.components[]`（blint 及版本）               | 合并进最终`metadata.tools`                  | —        | 满足 PRE-7-RQ-06 编制者/工具可追溯                                                                            |

#### 2.1.5 深度模式与符号数据库

| 选项                         | 默认 | 取舍                                                                                                                  |
| ---------------------------- | ---- | --------------------------------------------------------------------------------------------------------------------- |
| `--deep` | 固定关闭 | 不提供启用配置，以控制 DEX 深度分析的耗时和附加产物 |
| `--use-blintdb`            | 关   | 需下载符号数据库镜像（`blint db --download`），可提升 native 组件版本识别率；作为部署期可选项                       |
| 单 APK 超时                  | 600s | 超时/失败仅记 warning，该 APK 回落为APK 根组件，不阻塞整体扫描                                                        |

#### 2.1.6 与权威元数据的合并去重

Android 组件信息存在多个来源，按优先级合并：

| 优先级 | 来源                                                | 提供内容                                                                | 特点                         |
| ------ | --------------------------------------------------- | ----------------------------------------------------------------------- | ---------------------------- |
| 1      | `packages.xml`（`android_apk_metadata` 子模块） | 已安装包全集、精确`versionCode/versionName`                           | Android 最权威的包清单       |
| 2      | `build.prop`                                      | Android 版本、安全补丁级别、SDK                                         | 平台级组件（`android`）    |
| 3      | **Blint（本节）**                             | APK 内 native so、dex、maven 版本文件、SDK/追踪器、`minSdk/targetSdk` | 补充包清单无法表达的内部组件 |
| 4      | `S09` 二进制版本检测                              | so/ELF 的通用库版本（OpenSSL、zlib 等）                                 | 与 3 互补，交叉验证          |

合并规则：

1. **同一 APK**：以 `packages.xml` 的 `versionName/versionCode` 为权威版本，Blint 结果用于补充子组件与属性
2. **去重键**：`(purl, version)`；EMBA 原生 `build_sbom_json_hashes_arr` 已按 SHA-512 + 名称 + 版本去重，Blint 产物哈希缺失时回退到 purl 键
3. **父子关系**：APK 为父组件，其 native so / dex / maven 归档为子组件，依赖边来自 Blint `dependencies[]`

#### 2.1.7 已知限制与缓解

| 限制                                                | 影响                        | 缓解                                                                 |
| --------------------------------------------------- | --------------------------- | -------------------------------------------------------------------- |
| APK 打包剥离库元信息（MASTG 官方声明）              | SBOM 天然不完整             | 定位为【最大化召回】；关键组件结合源码侧 SBOM 补齐                   |
| 不识别 Maven/Gradle 依赖                            | OkHttp 等常见库不以组件出现 | `*.version` 文件命中时输出 maven purl；否则标记 `unknown` 待补录 |
| 无 license 检测                                     | 许可证字段缺失              | 许可证由`F14`、源码侧 SBOM、人工补录提供                           |
| 输入无效时退出码 0 且不产出文件                     | 任务可能假成功              | 子模块断言输出文件存在；平台侧再校验主 SBOM 存在性                   |
| 无签名证书/导出组件/debuggable 等 Manifest 加固分析 | 不覆盖 APK 安全测试项       | 属安全测试范畴（MobSF/MASTG），不在本模块范围                        |
| `--deep` 固定关闭                  | 深度分析才能识别的 SDK/追踪器可能缺失              | 结合源码侧 SBOM 或其他分析结果补充                                    |
| native so 版本仅来自 ELF notes 或 blintdb           | 版本可能为空                | 版本置空 +`confidence=0.5`，与 S09 结果交叉补充                    |

### 2.2. RTOS 固件扫描设计

RTOS 固件（FreeRTOS、RT-Thread、Zephyr、NuttX 等）与 Linux 固件的根本区别：

| 特征           | Linux 固件              | RTOS 固件                    |
| :------------- | :---------------------- | :--------------------------- |
| 包管理器数据库 | 有（dpkg/opkg/apk）     | **无**                 |
| ELF 符号表     | 通常保留                | 通常剥离                     |
| 版本字符串     | 丰富                    | **稀少**               |
| 文件系统       | 有（squashfs/ext4）     | **通常无**（裸二进制） |
| 识别方法       | 包管理器解析 + 文件哈希 | **二进制特征匹配**     |

### 2.3 SDK 制品扫描

| SDK 类型                                | 典型内容                           | SBOM 提取策略                      |
| :-------------------------------------- | :--------------------------------- | :--------------------------------- |
| **Linux SDK** (Yocto/Buildroot)   | `tmp/deploy/`, `staging/` 目录 | 扫描`Packages`/`manifest` 文件 |
| **Android NDK/SDK**               | 预编译工具链 + 库                  | 解析`package.xml`, 字符串匹配    |
| **MCU SDK** (STM32/NXP/nRF)       | HAL 库 + 驱动 + 示例               | 扫描`CHANGELOG`, 版本头文件      |
| **芯片厂商 SDK** (ESP-IDF/Nordic) | 组件管理器 (`idf_component.yml`) | 解析 YAML 依赖文件                 |
| **通用 C/C++ 依赖**               | `.a`/`.so` 静态库              | S09 二进制版本检测                 |

## 3. 数据模型与 CRA 合规映射

### 3.1 CRA 条款 → CycloneDX 字段

| CRA 要求                          | SBOM 字段                                                        | 数据来源                                                 |
| --------------------------------- | ---------------------------------------------------------------- | -------------------------------------------------------- |
| PRE-6-RQ-01：制造商名称           | `metadata.component.supplier`（或厂商属性）                    | 固件元数据 / 任务录入（手动指定）                        |
| PRE-6-RQ-01：产品名称             | `metadata.component.name`                                      | 固件文件名 /`build.prop` / 任务录入                    |
| PRE-6-RQ-01：软件标识符           | `component.purl` + `component.cpe`                           | Blint（`pkg:android/...`）、包管理器 purl、CPE 推断    |
| PRE-7-RQ-01：组件清单             | `components[]`                                                 | S08（原生 + 自定义）/ S09 / S24-S25 聚合                 |
| PRE-7-RQ-02：生产商/名称/版本     | `components[].supplier`、`name`、`version`                 | 解析结果 + 归一化                                        |
| PRE-7-RQ-03：SBOM（至少顶层依赖） | `components[]`（顶层）                                         | 默认输出；`SBOM_UNTRACKED_FILES=1` 扩展覆盖            |
| PRE-7-RQ-04：结构化机器可读       | CycloneDX JSON                                                   | `F15` 产出                                             |
| PRE-7-RQ-05：新版本新 SBOM        | 每次扫描独立归档（BOM`version` 递增）                          | 任务级 SBOM                                              |
| PRE-7-RQ-06：编制者/版本/时间标签 | `metadata.tools`、`metadata.version`、`metadata.timestamp` | 后处理补全（EMBA + Blint 工具信息）                      |
| PRE-7-RQ-07：唯一标识符与依赖关系 | `components[].purl/cpe`、`dependencies[]`                    | Blint`dependencies[]` + EMBA `build_dependency_tree` |
| PRE-8：硬件组件                   | `metadata` 硬件信息 / 硬件类组件                               | 架构检测（ARM/MIPS/RISC-V）、SoC/模组人工录入（HBOM）    |

### 3.2 组件表字段（与平台既有 SBOM Component 表对齐）

| 字段         | 来源示例                                                                      |
| ------------ | ----------------------------------------------------------------------------- |
| `name`     | `ab`（opkg）、`com.example.app`（Android 包名）、`libssl.so`            |
| `version`  | `1.3.42-1`、`versionName`、ELF notes 版本                                 |
| `group`    | `OpenWRT`（EMBA group）、Maven groupId                                      |
| `type`     | CycloneDX`application` / `library` / `file`                             |
| `cpe`      | `cpe:2.3:a:...`（EMBA 生成，或后处理推断）                                  |
| `purl`     | `pkg:opkg/...`、`pkg:android/...`、`pkg:maven/...`                      |
| `supplier` | 包维护者 /`Unknown`                                                         |
| 置信度       | 属性`gst:confidence`（来自 `EMBA:sbom:confidence` 或 Blint `evidence`） |
| 证据/路径    | 属性`EMBA:sbom:source_location:*`、`gst:blint:*`                          |

### 3.3 属性命名空间约定

| 前缀            | 来源       | 示例                                               |
| --------------- | ---------- | -------------------------------------------------- |
| `EMBA:sbom:*` | EMBA 原生  | `source_path`、`confidence`、`dependency`    |
| `gst:blint:*` | Blint 桥接 | `raw_purl`、`technique`、`service`、`deep` |
| `gst:*`       | 平台后处理 | `source`（packages.xml/blint）、`confidence`   |

## 4. 已确定的设计决策

| 决策               | 结论                                                                                                           |
| ------------------ | -------------------------------------------------------------------------------------------------------------- |
| APK 组件识别工具   | **Blint**（OWASP dep-scan，MIT），经自定义 S08 子模块在 **EMBA 内**执行，与原生子模块同构写入 SBOM |
| Android 权威包清单 | 保留`packages.xml`/`build.prop` 解析子模块，与 Blint 结果按优先级合并（6.5）                               |
| `.apk` 二义性    | 必须以 zip 魔数 +`AndroidManifest.xml` 甄别 Android APK 与 Alpine `.apk`，避免与原生子模块冲突             |
| 深度模式           | 固定关闭，不传递 `--deep`，不提供启用配置                                               |
| Blint 失败策略     | 降级不阻塞：单 APK 失败仅告警，整体扫描继续；结果标记部分识别                                                  |
| 并发模型           | EMBA 全局串行（`maxConcurrent=1`），日志目录按任务隔离                                                       |
| 成功判定           | 退出码 + 主 SBOM 存在 + schema 校验 三者同时满足，规避退出码 0 无产物                                          |
| SBOM 格式          | CycloneDX JSON（EMBA 产出 1.5、Blint 产出 1.6，后处理统一为平台 CycloneDX 版本，预留 1.7 升级）                |
| 非标准 purl        | `pkg:file/*` 归一化为 `pkg:generic/*`，原值保留在 `gst:blint:raw_purl`                                   |
| 版本管理           | 每次扫描生成独立 SBOM 并归档，与固件版本 1:1 绑定（PRE-7-RQ-05）                                               |
| RTOS/SDK           | v1 以框架 + 通用签名模式落地，按需启用，未知组件标记`unknown:<sha256>` 待人工补录                            |

## 5. 风险与局限

| 风险                        | 影响                                | 缓解措施                                                        |
| --------------------------- | ----------------------------------- | --------------------------------------------------------------- |
| Android 分区镜像加密        | 无法提取文件系统                    | 要求提供未加密 OTA 包或工厂镜像                                 |
| APK 元信息被剥离            | SBOM 天然不完整（MASTG 官方声明）   | 定位为最大化召回；结合源码侧 SBOM、人工补录                     |
| Blint 不识别常见 Maven 依赖 | OkHttp 等库缺失                     | 上游跟进；`*.version` 命中时输出 maven purl                   |
| 无 license 识别             | PRE-7 许可证字段缺口                | `F14` + 源码侧 SBOM + 人工补录                                |
| RTOS 符号剥离               | 无法精确识别版本                    | 依赖字符串特征与签名库；标注版本精度等级                        |
| RTOS/SDK 签名库覆盖不足     | 组件漏报                            | 通用签名模式 + 按需扩展，`unknown` 占位                       |
| 扫描耗时（大固件/多 APK）   | 任务排队时间长                      | profile 裁剪（`SBOM_MINIMAL`）、固定关闭 deep、超时兜底 |
| 磁盘占用                    | 解包文件系统 + Blint 中间产物占空间 | 任务成功后清理策略、日志目录容量规划                            |
| 版本精度限制                | 部分组件只能识别大版本              | SBOM 属性中标注置信度与版本精度，供人工复核                     |
