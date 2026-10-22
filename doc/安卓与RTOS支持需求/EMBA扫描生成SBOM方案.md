# 需求

## [PRE-6] Product identification

本子条款描述记录相关信息以使产品能够被识别的活动，其目的包括漏洞处理、SBOM 生成与验证，以及漏洞信息共享和报告。

**[PRE-6-RQ-01]** 产品应至少通过提供下列信息实现可识别：

- 制造商名称；
- 产品名称；
- (对于硬件):任何硬件产品标识符，如适用；
- (用于软件):任何软件产品标识符，如适用。

**[PRE-6-RQ-02]** 如果产品同时包含硬件和软件，应分别提供 [[**PRE-6-RQ-01**]](#req-pre-6-rq-01) 规定的产品标识信息。

## [PRE-7] Identification of software components

## [PRE-8] Identification of hardware components

需求总结：

扫描固件或二进制制品（Android、RTOS、SDK、Linux）生成SBOM

# EMBA

## 系统介绍

[EMBA](https://github.com/e-m-b-a/emba)（Embedded Analyzer）是一个**开源、自动化**的嵌入式设备固件安全分析框架，专门设计用于**逆向工程和安全评估**。

开源许可证：GPL-3.0

除了作为SBOM源的二进制分析机制外，_EMBA_ 现在能够从以下来源提取详细信息：

- ✅Binaries and libraries (S09 - excluded from sbom-minimal profile)
- ✅Linux Kernel (S24)
- ✅Linux Kernel+modules (s25)
- ✅Linux distribution identification (s06)
- ✅RPM package management system (S08)
- ✅RPM packages (S08)
- ✅Debian package management system (S08)
- ✅Debian deb Package support (S08)
- ✅OpenWRT Package management system (S08)
- ✅OpenWRT ipk Package support (S08)
- ✅Python PIP package management system (S08)
- ✅Python requirements files (S08)
- ✅Python Pipfile.lock (S08)
- ✅Python poetry (S08)
- ✅Python wheel (S08)
- ✅FreeBSD pkg packages (S08)
- ✅Java archives (jar, war - S08)
- ✅Alpine APK package support (S08)
- ✅Rust cargo.lock (S08)
- ✅Ruby gem (S08)
- ✅JavaScript - npm (S08)
- ✅Windows binary exif data (S08)
- ✅Windows binary extraction and analysis (S08)
- ✅C/C++ package manager - conanfile (S08)
- ✅PHP composer (S08)
- ✅Perl CPAN (S08)

## 系统架构与流程

EMBA的功能主要由以下几类模块实现，可以自定义模块来增强功能，便于扩展。

| Category    | Prefix          | Purpose                            | Example Task                         |
| :---------- | :-------------- | :--------------------------------- | :----------------------------------- |
| **P** | Pre-Analysis    | 准备固件，解压文件，进行初步扫描。 | 解压固件（如ZIP文件）。              |
| **S** | Static Analysis | 在不运行代码的情况下检查文件。     | 检查代码中是否存在已知的漏洞。       |
| **F** | Final Reports   | 生成摘要、软件物料清单。           | 创建一份所有软件组件的清单（SBOM）。 |

## 系统优缺点

优点：

- 模块化，便于扩展

缺点：

- 官方不支持 Android、 RTOS 以及 SDK 的组件扫描，需要自己实现集成

# 方案

## 总体架构

EMBA 原生覆盖了 Linux 生态的 SBOM 生成，但官方不支持 Android、RTOS 和 SDK。方案核心策略是在 EMBA 框架内开发自定义模块，补充这三类平台的组件识别能力。

```
固件输入
  ↓
P阶段: 解压/提取 (P05/P25/P55)
  ↓
预处理: 分区挂载 / 文件系统提取
  ↓
S阶段: 静态分析
  ├── S06: Linux 发行版识别
  ├── S08: 包管理器解析 (原生 + 自定义子模块)
  │     ├── debian_pkg_mgmt (原生)
  │     ├── apk_pkg_mgmt (原生)
  │     ├── android_pkg_sbom (自定义 - Android)
  │     ├── rtos_component_sbom (自定义 - RTOS)
  │     └── sdk_sbom (自定义 - SDK)
  ├── S09: 二进制版本检测 (通用，覆盖所有平台)
  └── S24/S25: 内核分析
  ↓
F阶段: 报告生成
  ├── F15: CycloneDX SBOM 生成
  └── F17: CVE 漏洞聚合
```

## 扫描流程

### 基于 EMBA 的标准扫描命令

```bash
# Linux 固件 (使用 EMBA 原生能力)
sudo ./emba -f <firmware.bin> -l <log_dir> -p ./scan-profiles/default-sbom.emba

# Android 固件 (含自定义模块)
sudo ./emba -f <firmware.bin> -l <log_dir> -p ./scan-profiles/android-sbom.emba

# RTOS 固件 (含自定义模块)
sudo ./emba -f <firmware.bin> -l <log_dir> -p ./scan-profiles/rtos-sbom.emba
```

### 自定义 scan profile 示例

```bash
# scan-profiles/android-sbom.emba
export QEMULATION=0
export BINARY_EXTENDED=1
export DISABLE_DEEP=0
MODULE_BLACKLIST=( "S99_grepit" )

# scan-profiles/rtos-sbom.emba
export QEMULATION=0
export BINARY_EXTENDED=0
export DISABLE_DEEP=1
```

## Android 固件扫描

### EMBA 已有能力

| 模块                     | 能力             | 说明                                      |
| :--------------------- | :------------- | :-------------------------------------- |
| **P25_android_ota.sh** | OTA 提取         | 使用 `payload_dumper.py` 解包 `payload.bin` |
| **S06**                | Linux 发行版识别    | 提取 `build.prop` 中的版本信息                  |
| **S08** 子模块            | Debian/APK 包管理 | 部分 Android 系统使用这些格式                     |
| **S09**                | 二进制版本检测        | 识别 OpenSSL、zlib 等常见库的版本                 |

### 差距分析

Android 固件包含 `system.img`、`vendor.img`、`product.img` 等分区镜像，EMBA 的 P25 模块**仅处理 OTA payload.bin**，不直接挂载分区镜像。此外：

- **`/system/packages.xml`** 是 Android 最权威的已安装包列表（类似 dpkg status），EMBA 未解析
- **`/vendor/etc/vintf/manifest.xml`** 包含 HAL 组件信息，EMBA 未提取
- **预编译 APK** 的 `AndroidManifest.xml` 中的版本信息未被利用

### 自定义模块: S08_submodule_android_apk_package_parser.sh

#### 解析策略

1. 搜索已挂载/解压的文件系统中的关键元数据文件
2. 解析 XML 提取组件名和版本号
3. 对每个识别的组件调用 EMBA 的 `build_sbom_json_component_arr` 输出 SBOM 条目

#### 关键数据源

| 文件路径                 | 内容                     | 提取方式                  |
| :------------------- | :--------------------- | :-------------------- |
| `packages.xml`       | 所有已安装 APK 列表 + 版本      | XML 解析 `<package>` 标签 |
| `build.prop`         | Android 版本、安全补丁级别、内核版本 | 键值对解析                 |
| `vintf/manifest.xml` | HAL 组件列表               | XML 解析                |
| `apex/` 目录           | APEX 模块列表              | 文件扫描                  |

#### 实现伪代码

```bash
S08_submodule_android_apk_package_parser() {
  module_log_init "${FUNCNAME[0]}"
  module_title "Android package SBOM generator"

  local lNEG_LOG=0
  local lFIRMWARE_PATH="${FIRMWARE_PATH}"

  # 解析 packages.xml
  local lPACKAGES_XML=$(find "$lFIRMWARE_PATH" -name "packages.xml" -type f 2>/dev/null)
  if [[ -n "$lPACKAGES_XML" ]]; then
    while IFS= read -r lPACKAGE_LINE; do
      local lNAME=$(echo "$lPACKAGE_LINE" | grep -oP 'name="[^"]*"' | cut -d'"' -f2)
      local lVERSION=$(echo "$lPACKAGE_LINE" | grep -oP 'version="[^"]*"' | cut -d'"' -f2)
      if [[ -n "$lNAME" && -n "$lVERSION" ]]; then
        build_sbom_json_component_arr "android_pkg" "$lNAME" "$lVERSION"
        lNEG_LOG=1
      fi
    done < <(grep '<package ' "$lPACKAGES_XML")
  fi

  # 解析 build.prop
  local lBUILD_PROP=$(find "$lFIRMWARE_PATH" -name "build.prop" -path "*/system/*" -type f 2>/dev/null | head -1)
  if [[ -f "$lBUILD_PROP" ]]; then
    local lANDROID_VER=$(grep "^ro.build.version.release=" "$lBUILD_PROP" | cut -d= -f2)
    local lSDK_VER=$(grep "^ro.build.version.sdk=" "$lBUILD_PROP" | cut -d= -f2)
    local lSECURITY_PATCH=$(grep "^ro.build.version.security_patch=" "$lBUILD_PROP" | cut -d= -f2)
    if [[ -n "$lANDROID_VER" ]]; then
      build_sbom_json_component_arr "android_platform" "android" "$lANDROID_VER"
    fi
  fi

  module_end_log "${FUNCNAME[0]}" "$lNEG_LOG"
}
```

## RTOS 固件扫描

### 核心挑战

RTOS 固件（FreeRTOS、RT-Thread、Zephyr、NuttX 等）与 Linux 固件的根本区别：

| 特征 | Linux 固件 | RTOS 固件 |
|:---|:---|:---|
| 包管理器数据库 | 有（dpkg/opkg/apk） | **无** |
| ELF 符号表 | 通常保留 | 通常剥离 |
| 版本字符串 | 丰富 | **稀少** |
| 文件系统 | 有（squashfs/ext4） | **通常无**（裸二进制） |
| 识别方法 | 包管理器解析 + 文件哈希 | **二进制特征匹配** |

### 两级识别策略

#### Level 1 - 字符串特征匹配（低成本，高覆盖）

从固件二进制中提取可读字符串，用正则匹配已知组件和版本：

```bash
# 已知 RTOS 组件版本字符串模式
RTOS_SIGNATURES=(
  "FreeRTOS V[0-9]+\.[0-9]+"
  "RT-Thread [0-9]+\.[0-9]+"
  "Zephyr version [0-9]+\.[0-9]+"
  "NuttX v[0-9]+\.[0-9]+"
  "mbedTLS [0-9]+\.[0-9]+"
  "lwIP [0-9]+\.[0-9]+"
  "wolfSSL [0-9]+\.[0-9]+"
  "newlib [0-9]+\.[0-9]+"
  "musl libc v[0-9]+\.[0-9]+"
  "ESP-IDF v[0-9]+\.[0-9]+"
)
```

#### Level 2 - 函数签名匹配（高成本，高精度）

参考 ONEKEY 和 GrammaTech 的方法：

1. 识别固件架构（ARM Cortex-M/RISC-V/MIPS）和加载地址
2. 使用 Ghidra/Radare2 反汇编
3. 提取函数特征向量（指令统计、控制流图特征）
4. 与已知函数签名数据库匹配

**推荐先实施 Level 1**，Level 2 作为后续增强。

### 自定义模块: S08_rtos_component_sbom.sh

#### 组件签名数据库

维护在 `config/sbom_signatures/rtos_components.json`：

```json
[
  {
    "component": "FreeRTOS",
    "version_patterns": ["FreeRTOS V([0-9]+\\.[0-9]+)"],
    "purl": "pkg:generic/freertos/freertos",
    "cpe": "cpe:2.3:a:amazon:freertos:*"
  },
  {
    "component": "RT-Thread",
    "version_patterns": ["RT-Thread ([0-9]+\\.[0-9]+)"],
    "purl": "pkg:generic/rt-thread/rt-thread"
  },
  {
    "component": "Zephyr",
    "version_patterns": ["Zephyr version ([0-9]+\\.[0-9]+)"],
    "purl": "pkg:generic/zephyr/zephyr-rtos"
  },
  {
    "component": "mbedTLS",
    "version_patterns": ["mbed TLS ([0-9]+\\.[0-9]+)", "mbedtls-[0-9]+\\.[0-9]+\\.[0-9]+"],
    "purl": "pkg:generic/arm/mbedtls"
  },
  {
    "component": "lwIP",
    "version_patterns": ["lwIP ([0-9]+\\.[0-9]+)"],
    "purl": "pkg:generic/lwip/lwip"
  }
]
```

#### 支持的 RTOS 组件

| 类别 | 组件 | 识别方式 |
|:---|:---|:---|
| RTOS 内核 | FreeRTOS, RT-Thread, Zephyr, NuttX, ThreadX | 字符串 + 函数签名 |
| 加密库 | mbedTLS, wolfSSL, OpenSSL, libsodium | 字符串 + 符号表 |
| TCP/IP 栈 | lwIP, PicoTCP, uIP | 字符串 + 二进制特征 |
| 标准库 | newlib, musl, picolibc, uClibc | 字符串 + ELF 段特征 |
| 文件系统 | LittleFS, FatFS, SPIFFS | 字符串匹配 |
| WiFi/BLE | ESP-IDF, NimBLE, Bluedroid | 字符串 + 专有格式 |

#### 实现伪代码

```bash
S08_rtos_component_sbom() {
  module_log_init "${FUNCNAME[0]}"
  module_title "RTOS component SBOM generator"

  local lNEG_LOG=0
  local lSIGNATURE_FILE="${CONFIG_DIR}/sbom_signatures/rtos_components.json"

  # 提取固件中所有可读字符串
  local lSTRINGS_LOG="${LOG_PATH_MODULE}/strings_output.txt"
  strings "${FIRMWARE_PATH}" > "$lSTRINGS_LOG" 2>/dev/null

  # 逐条匹配已知签名
  while IFS= read -r lENTRY; do
    local lCOMP_NAME=$(echo "$lENTRY" | jq -r '.component')
    local lPURL=$(echo "$lENTRY" | jq -r '.purl // empty')

    while IFS= read -r lPATTERN; do
      local lVERSION=$(grep -oP "$lPATTERN" "$lSTRINGS_LOG" | head -1 | grep -oP '[0-9]+\.[0-9]+[0-9.]*')
      if [[ -n "$lVERSION" ]]; then
        local lPROPERTIES_ARR=()
        [[ -n "$lPURL" ]] && lPROPERTIES_ARR+=("purl:${lPURL}")
        build_sbom_json_component_arr "rtos_component" "$lCOMP_NAME" "$lVERSION" "${lPROPERTIES_ARR[@]}"
        lNEG_LOG=1
      fi
    done < <(echo "$lENTRY" | jq -r '.version_patterns[]')
  done < <(jq -c '.[]' "$lSIGNATURE_FILE")

  # 未匹配的二进制标记为 unknown
  if [[ -f "${SBOM_LOG_PATH}/"rtos_component_*.json 2>/dev/null ]]; then
    local lSHA256=$(sha256sum "${FIRMWARE_PATH}" | cut -d' ' -f1)
    build_sbom_json_component_arr "rtos_binary" "unknown-rtos-component" "unknown" "sha256:${lSHA256}"
  fi

  module_end_log "${FUNCNAME[0]}" "$lNEG_LOG"
}
```

## SDK 制品扫描

### SDK 类型分析

| SDK 类型 | 典型内容 | SBOM 提取策略 |
|:---|:---|:---|
| **Linux SDK** (Yocto/Buildroot) | `tmp/deploy/`, `staging/` 目录 | 扫描 `Packages`/`manifest` 文件 |
| **Android NDK/SDK** | 预编译工具链 + 库 | 解析 `package.xml`, 字符串匹配 |
| **MCU SDK** (STM32/NXP/nRF) | HAL 库 + 驱动 + 示例 | 扫描 `CHANGELOG`, 版本头文件 |
| **芯片厂商 SDK** (ESP-IDF/Nordic) | 组件管理器 (`idf_component.yml`) | 解析 YAML 依赖文件 |
| **通用 C/C++ 依赖** | `.a`/`.so` 静态库 | S09 二进制版本检测 |

### 自定义模块: S08_sdk_sbom.sh

#### 关键文件扫描模式

```bash
SDK_COMPONENT_FILES=(
  "*/idf_component.yml"          # ESP-IDF 组件
  "*/package.xml"                # ROS/catkin, STM32Cube
  "*/CMakeLists.txt"             # 版本号提取
  "*/VERSION"                    # 通用版本文件
  "*/CHANGELOG.md"               # 首行版本提取
  "*/.repo/manifest.xml"         # repo 工具管理的 SDK
  "*/meta-*/recipes-*/BBPATH"    # Yocto layer
  "*/Kconfig"                    # 内核配置
)

VERSION_DEFINES=(
  "#define.*VERSION"
  "#define.*_MAJOR"
  "#define.*_MINOR"
  "#define.*_PATCH"
)
```

#### 实现伪代码

```bash
S08_sdk_sbom() {
  module_log_init "${FUNCNAME[0]}"
  module_title "SDK SBOM generator"

  local lNEG_LOG=0

  # 扫描 idf_component.yml (ESP-IDF)
  while IFS= read -r lCOMP_FILE; do
    while IFS= read -r lCOMP_ENTRY; do
      local lNAME=$(echo "$lCOMP_ENTRY" | yq e '.name' -)
      local lVERSION=$(echo "$lCOMP_ENTRY" | yq e '.version' -)
      if [[ -n "$lNAME" && "$lVERSION" != "null" ]]; then
        build_sbom_json_component_arr "sdk_component" "$lNAME" "$lVERSION"
        lNEG_LOG=1
      fi
    done < <(yq e '.dependencies[]' "$lCOMP_FILE" 2>/dev/null)
  done < <(find "$FIRMWARE_PATH" -name "idf_component.yml" -type f 2>/dev/null)

  # 扫描头文件中的版本宏
  while IFS= read -r lHEADER; do
    local lCOMP_NAME=$(basename "$(dirname "$lHEADER")")
    local lVERSION=$(grep -oP '#define\s+\w*VERSION\w*\s+["'"'"']?\K[0-9]+\.[0-9]+[0-9.]*' "$lHEADER" 2>/dev/null | head -1)
    if [[ -n "$lVERSION" ]]; then
      build_sbom_json_component_arr "sdk_header" "$lCOMP_NAME" "$lVERSION"
      lNEG_LOG=1
    fi
  done < <(find "$FIRMWARE_PATH" -name "*.h" -exec grep -l '#define.*VERSION' {} \; 2>/dev/null | head -50)

  module_end_log "${FUNCNAME[0]}" "$lNEG_LOG"
}
```

## SBOM 输出与 CRA 合规映射

| CRA 要求 | SBOM 字段 | 数据来源 |
|:---|:---|:---|
| PRE-6-RQ-01: 制造商名称 | `metadata.manufacturer` | 固件元数据 / 手动指定 |
| PRE-6-RQ-01: 产品名称 | `metadata.product` | 固件文件名 / build.prop |
| PRE-6-RQ-01: 软件标识符 | `component.purl` + `component.cpe` | 自动推断 |
| PRE-7: 软件组件清单 | `components[]` | 所有 S08/S09 模块输出聚合 |
| PRE-8: 硬件组件清单 | `metadata.hardware` | 架构检测 (ARM/MIPS/RISC-V) |

## 自定义模块开发规范

### 文件结构

```
emba/
  modules/
    S08_android_package_sbom.sh   # Android 模块
    S08_rtos_component_sbom.sh    # RTOS 模块
    S08_sdk_sbom.sh               # SDK 模块
  config/
    sbom_signatures/
      android_packages.json       # Android 包签名库
      rtos_components.json        # RTOS 组件签名库
      sdk_components.json         # SDK 组件签名库
```

### 模块模板

```bash
#!/bin/bash

S08_<module_name>() {
  module_log_init "${FUNCNAME[0]}"
  module_title "<模块标题>"

  local lNEG_LOG=0

  # === 核心分析逻辑 ===

  module_end_log "${FUNCNAME[0]}" "$lNEG_LOG"
}
```

### 关键 EMBA 接口

- `module_log_init` / `module_end_log`: 模块生命周期管理
- `build_sbom_json_component_arr <packaging_system> <name> <version> [properties...]`: 输出 SBOM 条目
- `print_output`: 控制台输出
- `write_csv_log`: CSV 日志记录
- `${FIRMWARE_PATH}`: 固件路径（已解压）
- `${LOG_PATH_MODULE}`: 模块日志目录
- `${SBOM_LOG_PATH}`: SBOM JSON 输出目录
- `${CONFIG_DIR}`: 配置文件目录

## 实施步骤

| 阶段 | 任务 | 产出 | 预计周期 |
|:---|:---|:---|:---|
| **Phase 1** | EMBA 环境搭建 + Linux 固件试扫描 | 基线 SBOM + 验证环境 | 1 周 |
| **Phase 2** | 开发 `S08_android_package_sbom.sh` | Android SBOM 能力 | 2 周 |
| **Phase 3** | 开发 `S08_rtos_component_sbom.sh` + 签名库 | RTOS SBOM 能力 | 2-3 周 |
| **Phase 4** | 开发 `S08_sdk_sbom.sh` | SDK SBOM 能力 | 1-2 周 |
| **Phase 5** | 集成测试 + 精度调优 | 生产级 SBOM 流程 | 1-2 周 |

## 局限性与风险

| 风险 | 影响 | 缓解措施 |
|:---|:---|:---|
| RTOS 二进制符号剥离 | 无法精确识别组件版本 | 优先依赖字符串特征；维护签名数据库 |
| Android 分区镜像加密 | 无法提取文件系统 | 要求提供未加密的 OTA 包或工厂镜像 |
| SDK 私有组件 | 无已知签名 | 标记为 `unknown:<sha256>`，后续人工补录 |
| 版本精度限制 | 部分组件只能识别大版本 | SBOM 中注明版本精度等级 |
| RTOS 类型未确定 | 签名库覆盖范围不足 | 采用通用签名模式，按需扩展 |
