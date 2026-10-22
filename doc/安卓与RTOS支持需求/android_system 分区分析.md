# android_system 分区分析

文件来源

`firmware/android_system.img` — 这是一个 Android `system` 分区（YAFFS1 文件系统），属于 EMBA 固件安全分析日志的一部分，大小约 184MB。

## 系统信息（来自 `build.prop`）

- Android 4.0.3 (Ice Cream Sandwich)，SDK 15
- 构建版本：`ICS.MBX.20140924`，编译于 2014-09-24（已过时约 12 年）
- 产品：MBX `f16ref` 参考板（Amlogic M1/MBOX 平台），armeabi-v7a
- **`test-keys` 签名 + `eng.root` 构建**（非正式 release-keys）
- 定位为机顶盒/电视类设备：无电池、无电话、无 GPS、无触摸屏，带以太网、DVB 数字电视、1080p 输出、遥控器光标 UI

## 目录结构

| 目录                                    | 内容                                                            |
| --------------------------------------- | --------------------------------------------------------------- |
| `app/`                                | 系统 APK（Launcher、Browser、Settings、Aml2DLauncher 等）+ odex |
| `bin/` `xbin/`                      | 系统可执行文件                                                  |
| `etc/`                                | 配置（wifi、permissions、vold.fstab、fw_env.config 等）         |
| `framework/`                          | Android 框架 jar                                                |
| `lib/`                                | 原生库（libMali、libamplayer、Mali GPU、8192cu.ko WiFi 驱动等） |
| `usr/` `fonts/` `media/` `tts/` | 输入映射、字体、媒体资源、TTS                                   |

## 安全相关观察点

1. `test-keys` + root 编译，可能存在调试后门
2. 2014 年的 ICS 系统，已知漏洞众多
3. `keyguard.enable=false`、`ro.platform.has.security=false`
4. `etc/` 下的 `ekcert.pem`、`security/`、`fw_env.config`（U-Boot 环境变量）
5. 厂商专有库 `libamplayer`、`libpickit`、`Aml2DLauncher` 等 Amlogic 定制组件

## Q&A

### 如何知道他是android system分区的

结论基于以下证据链（均为只读观察）：

**1. 目录路径本身**

```
.../firmware/yaffs1_extracted
```

- `firmware/` —— EMBA 固件分析产物目录
- `yaffs1_extracted` —— 固件里的 YAFFS1 镜像被解出来。YAFFS1 是 NAND Flash 常用文件系统，Android 设备 system/boot 镜像常用它（或 UBIFS/ext4）
- 这个目录在 `yaffs1_extracted` 顶层，说明解出的是固件中的**某一个分区镜像**（与之并列通常还有 boot、recovery、userdata 等）

**2. 顶层结构是 Android system 分区的标准布局**

```
/app  /bin  /xbin  /etc  /fonts  /framework  /lib  /media  /tts  /usr  /data(无)  /build.prop
```

这是 AOSP `system.img` 挂载后的经典结构：

- `build.prop` —— Android 独有的系统属性文件，**最强证据**
- `framework/` —— 存放 `framework.jar`、`services.jar` 等 Android 框架
- `app/` —— 系统预装 APK（`Settings.apk`、`Launcher2.apk`、`PackageInstaller.apk`）+ `.odex`（Dalvik 预编译字节码，Android 特有）
- `xbin/` —— Android 专有（su、busybox 通常在这）
- `bin/` `lib/` `etc/` —— Android 基于 Bionic/自定义 rootfs 的系统目录

**3. `build.prop` 内容直接确认**

```
ro.build.version.release=4.0.3
ro.product.cpu.abi=armeabi-v7a
dalvik.vm.heapstartsize=5m
ro.build.fingerprint=MBX/f16ref/...
```

- `ro.*` 属性、Dalvik 堆配置、`armeabi-v7a` ABI —— 全是 Android 专属字段
- 若是 `userdata` 分区不会是这个结构（那里面是 `/data/app`、`/data/data`）
- 若是 `boot` 分区则是 `kernel` + `ramdisk`，不会是完整 rootfs

**4. 反向排除**

- 不是 `recovery`：没有 `recovery-from-boot.p`、`etc/recovery.fstab` 特征（且通常结构更精简）
- 不是 `vendor` 分区：ICS 时代 vendor 分区尚未普及，且这里包含 `framework/`、`app/` 等 system 核心目录

**一句话**：路径显示它是固件里解出的 YAFFS1 分区镜像；目录结构（`build.prop` + `framework/` + `app/*.apk`）与 AOSP `system.img` 完全吻合，因此判定为 Android system 分区。

### 什么是 AOSP

AOSP 是 **Android Open Source Project（安卓开源项目）** 的缩写，简单来说，它就是 **安卓系统的“源代码本体”和开放开发框架**。

可以从这几个层面理解：

**一、AOSP 是什么？**

- **官方定义**：由 Google 发起并维护的一个 **开源项目**，提供构建 Android 操作系统所需的全部源代码、文档和工具。
- **本质**：一个 **公开的代码仓库 + 开发社区**，任何人都可以查看、下载、编译、修改。
- **协议**：主要使用 **Apache License 2.0**，非常宽松，允许商用和二次开发。

👉 你可以把它理解为：

> **Android 的“纯净源码版”，没有 Google 服务、没有厂商定制，只有最原始的系统骨架。**

**二、AOSP 包含什么？**

一个完整的 AOSP 源码树，大致包括：

| 组成部分                  | 说明                                          |
| ------------------------- | --------------------------------------------- |
| **Linux 内核**      | Android 基于 Linux，AOSP 包含适配后的内核源码 |
| **系统库**          | 如 Bionic（C 库）、OpenGL、SQLite、WebKit 等  |
| **Android Runtime** | ART（Android Runtime），负责运行应用          |
| **框架层**          | 应用框架 API（Activity、Window、Package 等）  |
| **系统应用**        | 电话、短信、设置、桌面等基础 App              |
| **构建工具**        | 编译系统（Soong/Bazel）、打包工具等           |

⚠️ **不包含** Google 专有组件：

- Google Play 服务（GMS）
- Google 应用（Play 商店、Gmail、Maps 等）
- 某些厂商闭源驱动

**三、AOSP 与“你手机上的安卓”有什么区别？**

| 对比项      | AOSP                   | 商业安卓（如小米、三星）     |
| ----------- | ---------------------- | ---------------------------- |
| 来源        | 开源代码               | AOSP + 厂商定制 + 闭源组件   |
| Google 服务 | ❌ 无                  | ✅ 通常有                    |
| 界面        | 原生 Android           | 各品牌 UI（MIUI、One UI 等） |
| 应用商店    | 无（只有基础包管理器） | Google Play 或厂商商店       |
| 使用场景    | 开发、研究、定制 ROM   | 普通消费者                   |

👉 你买到的手机安卓 = **AOSP + 厂商定制 + Google 服务（海外版）**

**四、AOSP 的主要用途**

1. **开发自定义 ROM**

   - LineageOS、Pixel Experience、crDroid 等都基于 AOSP
   - 刷机爱好者的主要来源
2. **设备厂商适配**

   - 手机/电视/车机厂商基于 AOSP 做系统定制
3. **系统级开发与调试**

   - 修改 Framework、System Server
   - 研究 Android 内部机制
4. **学习与科研**

   - 理解操作系统设计
   - 分析安全机制、性能优化

**五、常见误解澄清**

- ❌ **AOSP ≠ 谷歌安卓**Google 的安卓是 AOSP + GMS，AOSP 只是基础。
- ❌ **AOSP 不能直接当手机系统用**缺少驱动、GMS、厂商适配，通常无法直接在商业设备上运行。
- ❌ **AOSP 不是完全由 Google 控制**
  虽然 Google 主导，但代码是公开的，社区也能参与贡献。

**六、如何获取 AOSP？**

- 官方源码：https://source.android.com/
- 代码仓库：https://android.googlesource.com/
- 下载工具：`repo`（Google 开发的仓库管理工具）

⚠️ 注意：完整 AOSP 源码 **超过 100GB**，编译需要高性能机器。

### Android 4.0.3 是这样，后续的安卓版本还有system分区吗，特征也是相同的吗

**还有 system 分区**，但从 Android 7~10 开始，它的**位置、打包方式和内部结构**都发生了变化，不能只靠顶层目录结构判断。

**仍然相同的部分**

核心骨架一直保留：

```
/system/build.prop        属性文件（仍在）
/system/bin/              可执行文件（app_process、linker 等）
/system/lib[64]/          原生库
/system/framework/        framework.jar、services.jar 等
/system/app/  /system/priv-app/   系统 APK
/system/etc/              配置
```

看到 `build.prop` + `framework/` + `app/*.apk` 基本仍可判定为 system。

**主要变化**

| 版本        | 变化                                                                                                                                                                                  |
| ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Android 5.0 | Dalvik → ART：`.odex` 变为 `.odex/.oat/.vdex/.art`，Xposed/逆向方式不同                                                                                                          |
| Android 7.0 | 引入**VNDK/Treble 前夜**，`/system/vendor` 逐渐拆到独立 `/vendor` 分区                                                                                                      |
| Android 8.0 | Treble：`/vendor`、`/system_ext` 独立分区；属性拆到 `build.prop` + `/vendor/build.prop` + `default.prop` 等多个文件                                                         |
| Android 9.0 | **system-as-root**：system 直接作为根文件系统挂载到 `/`，`/system` 变成其子目录；新增 `/product` 分区                                                                     |
| Android 10  | **动态分区（super.img）**：system/vendor/product 被打包进一个 `super` 逻辑卷里，固件里不再有独立的 `system.img` 裸镜像；引入 **APEX** 模块（`/system/apex/*.apex`） |
| Android 11+ | APEX 承载更多核心组件（Conscrypt、Media 等），`framework/` 里 jar 变少                                                                                                              |
| Android 12+ | 主线模块化加强，`/system_ext`、`/apex` 成为分析重点                                                                                                                               |

**对固件分析的影响**

1. **老设备（如你这个 4.0.3）**：YAFFS/JFFS 裸分区 → 直接解出就是完整 system 目录。
2. **新设备**：
   - 文件系统多为 **ext4/f2fs**（YAFFS 基本绝迹，因为存储从 NAND 换成 eMMC/UFS）
   - 镜像常是 **EROFS/ext4**，且藏在 **super.img（动态分区）** 里，需要先 `lpunpack` 拆出 `system.img` 再挂载
   - A/B 设备有 `system_a`/`system_b`
3. **识别特征仍通用**：`build.prop`（或 `etc/build.prop`）、`framework/`、`app/`、`bin/app_process*` —— 这些跨版本都能用。

**一句话**：system 分区概念延续至今，但 Android 9 之后挂载方式（system-as-root）、Android 10 之后打包方式（动态分区 super.img）、Android 5 之后执行格式（ART）、Android 8 之后边界（Treble/APEX）都变了，分析流程需按版本调整。

### 不同分区对于提取组件的价值

**分区价值排序**

**高价值（必扫）**

| 分区                                    | 能扫出的组件                                                                                                                                                                                                                                               |
| --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `system`                              | AOSP/框架版本（`build.prop`、`framework/*.jar`）、系统 APK（`/system/app`、`/system/priv-app`）、原生二进制（`/system/bin`、`/system/xbin`，busybox/toybox/su 等）、`.so` 库（bionic、skia、openssl、sqlite、webkit）、预置字体/TTS/渲染引擎 |
| `vendor`                              | SoC 厂商专有组件（Qualcomm/MTK/Amlogic HAL、固件 blob、DSP/GPU 库）、驱动用户态部分、厂商 SDK（如 MTK/高通诊断工具）、自带编译的开源库（常带 CVE）                                                                                                         |
| `boot`/`recovery`（内核 + ramdisk） | Linux 内核版本、内核配置、init 脚本、内核模块（`.ko`）、ramdisk 里的 busybox、内嵌的 dtb、bootloader 相关                                                                                                                                                |
| `odm`/`oem`                         | 品牌定制 APK、预装第三方应用（广告/统计 SDK 是 SBOM 重点）                                                                                                                                                                                                 |

**中等价值**

| 分区                         | 能扫出的组件                                                                              |
| ---------------------------- | ----------------------------------------------------------------------------------------- |
| `product`                  | Google GMS 套件、预装 app、壁纸/铃声等资源                                                |
| `system_ext`（Android 9+） | Treble 拆分出的系统扩展，含 framework 扩展 jar 和 APK                                     |
| `userdata`/`cache`       | 几乎无静态 SBOM 价值；但 factory image 里若带`data/` 可能含预装 APK、配置、第三方库副本 |

**低价值但别忽略**

- `metadata`、`misc`、`persist`：无组件，但 `persist` 常含厂商调试残留
- `super.img`（动态分区）：里面嵌套 `system/vendor/product/system_ext`，必须先拆开再扫
- `dtbo`、`vbmeta`：签名/校验元数据，用于验证链分析而非 SBOM

**各分区常见可识别文件类型**

- **ELF**（bin/lib/lib64/odex/vdex）→ 内嵌字符串版本、`.comment` 段、符号表
- **APK**（assets/ 里的 .so、`classes.dex`、`META-INF/MANIFEST.MF`）→ HAC-1 / AndroParts 类工具可提取内嵌原生库
- **jar**（`framework/*.jar`、`services.jar`）→ AOSP 版本、依赖的开源 Java 库
- **内核** → `Linux version x.y.z`、模块 vermagic
- **脚本**（`init*.rc`、`*.sh`、`etc/init.d`）→ 启动的第三方守护进程
- **配置/证书**（`etc/` 下 openssl、ca-certificates）→ TLS 栈版本线索

**结合当前这份固件**

`build.prop` 已给出基线：Android 4.0.3、SDK 15、`test-keys`、MBX/f16ref（Amlogic 类板）。可扫目标：

- `framework/`（28M）→ AOSP 框架 jar + 可能的厂商 jar
- `lib/`（56M）→ 本机 `.so` 版本字符串，开源库是主要 CVE 来源
- `app/`（60M）→ 系统 APK 内嵌 so
- `etc/`（12M）→ init 脚本、证书、DNS/媒体配置
- `bin`+`xbin`（5.5M）→ native 工具（busybox 等）

**结论**：`system`、`vendor`、`boot`、`odm/product` 都要扫，`data` 一般跳过（除非是出厂镜像预置了应用）。扫描顺序建议 `boot` → `system` → `vendor` → `odm/product`，`super`/`vbmeta` 先解包。

### .odex 文件是什么，对EMBA BOM扫描有帮助吗

**.odex 是什么**

**Odex = Optimized DEX**，是 Dalvik 时代（Android 4.x，即你这个固件）对 DEX 字节码做**预优化/预编译**后的产物。

实测这个固件里的文件：

```
$ file app/Settings.odex
app/Settings.odex: Dalvik dex file (optimized for host) version 036

$ xxd app/Settings.odex | head
00000000: 6465 790a 3033 3600 ...   ← 魔数 "dey\n036"（odex 专用）
00000030: 6465 780a 3033 3500 ...   ← 内嵌完整 "dex\n035"（标准 DEX）
```

要点：

- 魔数是 `dey`（不是 `dex`），version 036 = ICS 时期的 odex 格式
- **内部直接嵌着一个完整的 `dex\n035`**，且文件尾有原始 `.apk`/`.jar` 的依赖信息
- 出现位置与源一一对应：`Settings.apk` + `Settings.odex`、`framework/framework.jar` + `framework.odex`
- 作用：开机时不用重新 dexopt，加快启动；Android 5+ 被 `.oat/.vdex/.art`（ART）取代

当前固件里共 **79 个 .odex**（59 个在 `app/`，其余在 `framework/` 等）。

**对 EMBA BOM/SBOM 扫描有帮助吗**

**直接帮助很有限——我查了你这次 EMBA 实际运行结果：**

| 模块                                | 结果                                                                                                                                                                                      |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `s08_main_package_sbom`           | 只识别了**12 个 Java jar**（`framework/*.jar` 的 MANIFEST），**0 个 APK、0 个 odex 进入 SBOM**；日志里 "No APK packages" 指的是 Alpine 的 apk 包管理器，与 Android APK 无关 |
| `f15_cyclonedx_sbom`              | CycloneDX JSON 里**apk=0、odex=0**，组件类型全是 `.so` 等原生库                                                                                                                   |
| `s09_firmware_base_version_check` | 对 699 个文件跑了 strings，**包含 79 个 odex**（`s09.../strings_bins/*odex.txt`），但版本命中几乎都是原生二进制（alsa、dnsmasq、hostapd…）                                       |

**结论：**

1. **EMBA 现状基本不吃 odex/APK** —— 它的 BOM 主要靠原生 ELF + 包管理器数据库 + jar MANIFEST。Android 应用层是空白。
2. **但 odex 本身有利用价值**（如果自己补扫描）：
   - 内嵌完整 DEX → `strings`/`baksmali` 可还原类名、第三方 SDK（如 bouncycastle、apache-xml 已通过 jar 被找到，SDK 版本常藏在 odex 字符串里）
   - 与 APK 配对可做包名/版本号提取，补 Android SBOM
   - 是漏洞面：ICS + test-keys 的 odex 代码可直接反编译审计
3. **想让 EMBA BOM 覆盖它**，方向是：`dexdump`/`jadx` 提取 `applicationId`+版本 → 注入 SBOM，或对 APK/odex 做独立的 Java 依赖分析（EMBA 的 `s08` 目前只扫 `.jar`）。

一句话：odex 是“APK 的预编译字节码缓存”，对当前这次 EMBA 扫描**几乎没有贡献**（0 进 SBOM，只被 strings 扫过），但对补全 Android 层 BOM 和代码审计是**有价值的原料**。

### 如何分析.apk文件的BOM

**方法（脚本 `apk_bom_analyzer.py`）**

APK 本质是 ZIP，BOM 关键字段提取路径：

| BOM 字段                             | 来源                                                                                                                                                |
| ------------------------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------- |
| 包名/版本/minSdk/targetSdk/权限/组件 | `AndroidManifest.xml`（二进制 AXML，用 `pyaxmlparser` 解析）                                                                                    |
| SHA-256/MD5                          | 整包哈希                                                                                                                                            |
| 签名证书 subject/issuer              | `META-INF/*.RSA`（PKCS#7）                                                                                                                        |
| 原生库`.so`                        | ZIP 内`lib/**.so` 条目                                                                                                                            |
| 三方库线索                           | **本固件 APK 全部被 strip 掉 `classes.dex`**（0/60 有 dex），代码在配对的 `.odex` 里 → 从 odex `strings` 匹配 `Lcom/...;` 类型描述符 |
| CycloneDX purl                       | `pkg:apk/<package>@<version>`                                                                                                                     |

**结果摘要**

```
APKs: 60 (ok=60) | with package: 60 | with classes.dex: 0 | with odex: 59
unique permissions: 125 | unique certs: 1 (AOSP 测试证书 android@android.com)
lib hints: amlogic-sdk, android-support-lib, apache-httpclient, neldtv-app, org.json
```

**非 AOSP 第三方应用（BOM 重点）：**

- `com.neldtv.apkstore`（含 `INSTALL_PACKAGES`，硬编码内网升级地址 `192.168.14.159`）
- `com.gsoft.appinstall`（`INSTALL_PACKAGES`）
- `com.example.Upgrade`、`com.fb.FileBrower`、`org.geometerplus...`（FBReader）、`com.amlogic.*`、`com.farcore.videoplayer`

**输出文件：**

- `apk_bom_out/apk_bom.csv` — 表格清单
- `apk_bom_out/apk_bom_detail.json` — 含权限列表详情
- `apk_bom_out/apk_bom_cyclonedx.json` — CycloneDX 1.5，可与 EMBA SBOM 合并

**重跑：**

```bash
python3 apk_bom_analyzer.py firmware -o apk_bom_out
```

局限：dex 被 strip，三方库只能靠 odex 字符串启发式；若要精确依赖版本，需 `baksmali`/`jadx` 反编译 odex 内嵌 dex 后做类级分析。

### pyaxmlparser

`from pyaxmlparser import APK` 是 **pyaxmlparser** 这个轻量级 Android APK 解析库的入口，用来读取 APK 里的 `AndroidManifest.xml`、资源、签名信息等，比 Androguard 轻很多。

**安装**

```
pip install pyaxmlparser
```

**基本用法**

```
from pyaxmlparser import APK

apk = APK("app.apk")

print(apk.package)        # 包名：com.example.app
print(apk.version_name)   # 版本名：1.0.0
print(apk.version_code)   # 版本号：1
print(apk.application)    # 应用名（label）
print(apk.icon_info)      # 图标资源信息
print(apk.icon_data)      # 图标原始字节

print(apk.get_activities())   # Activity 列表
print(apk.get_services())     # Service 列表
print(apk.get_receivers())    # BroadcastReceiver 列表
print(apk.get_providers())    # ContentProvider 列表

print(apk.get_permissions())  # 权限列表
print(apk.get_main_activity())  # 启动 Activity

print(apk.get_min_sdk_version())
print(apk.get_target_sdk_version())

print(apk.is_signed())
print(apk.is_signed_v1(), apk.is_signed_v2(), apk.is_signed_v3())
```

**常用构造参数**

```
APK(filename, raw=False, skip_analysis=False, testzip=False)
```

* `filename`：APK 路径，或 APK 字节（配合 `raw=True`）
* `skip_analysis=True`：不解析 manifest，速度更快
* `testzip=True`：校验 APK 的 ZIP 完整性

**从字节加载**

```
with open("app.apk", "rb") as f:
    data = f.read()

apk = APK(data, raw=True)
print(apk.package)
```

**典型用途**

* 自动化提取包名 / 版本号
* CI 里校验 APK 信息
* 安全扫描：权限、组件暴露、SDK 版本、签名方案
* 应用商店 / 资产管理：应用名、图标、版本

### pyaxmlparser 工作原理

`pyaxmlparser` 的本质是：**用纯 Python 把 APK 里的“二进制格式”按 Android 规范读出来，再包装成好用的 Python 对象**。它不反编译代码，也不跑 Android SDK，只做“静态元数据提取”。

**一、APK 本质：ZIP 包**

APK 其实就是 ZIP 文件，`pyaxmlparser` 第一步就是用标准库：

```python
import zipfile
zf = zipfile.ZipFile("app.apk")
```

然后从里面读关键成员：

- `AndroidManifest.xml`：二进制 XML
- `resources.arsc`：编译后的资源表
- `META-INF/*.RSA/*.SF`：V1 签名
- APK Signing Block：V2 / V3 签名
- `classes.dex`：一般不去解析字节码

**二、解析 AndroidManifest.xml：AXML → XML**

APK 里的 `AndroidManifest.xml` 不是普通 XML，而是 **Binary XML（AXML）**，结构大概是：

```
ChunkHeader
StringPool  <- 所有字符串
ResourceMap
StartTag / EndTag / Text
属性值可能是字符串，也可能是资源引用 @string/xxx
```

pyaxmlparser 的流程是：

1. `AXMLParser` 按 chunk 读二进制
   - 解析字符串池（UTF-8 / UTF-16）
   - 解析命名空间
   - 解析 start-tag / end-tag / attribute
2. `AXMLPrinter` 把事件流转成 `lxml.etree` 的 XML 树
3. 你就可以像读普通 XML 一样拿：
   - `package`
   - `versionCode`
   - `versionName`
   - `activity/service/receiver/provider`
   - `uses-permission`

也就是：**二进制 AXML → 事件流 → lxml DOM → Python 属性**

**三、解析 resources.arsc：把 `@string/app_name` 变成真字符串**

Manifest 里经常写：

```xml
android:label="@string/app_name"
android:icon="@mipmap/ic_launcher"
```

这些不是字符串，而是 **32 位资源 ID**：

```
0x7F 01 0032
│   │  └── entry id
│   └----- type id（string/drawable...）
└--------- package id（0x7F = 应用资源）
```

`ARSCParser` 会解析 `resources.arsc`：

- 资源表头
- 包 Package
- 类型 Spec / Type
- 配置 Config（语言、密度、横竖屏等）
- 具体 Entry

于是：

```python
apk.get_app_name()  # @string/app_name -> "我的应用"
apk.get_app_icon()  # @mipmap/ic_launcher -> res/drawable-xxhdpi/ic_launcher.png
```

**四、签名怎么处理**

**V1 签名**

读 `META-INF/CERT.RSA`，用 `asn1crypto` 解析 PKCS#7 / X.509 证书。

**V2 / V3 签名**

读 APK 末尾前面的 **APK Signing Block**：

- magic: `APK Sig Block 42`
- V2 ID: `0x7109871a`
- V3 ID: `0xf05368c0`

解析签名块里的 signer / digest / certificate。

> 注意：pyaxmlparser 主要是“读签名信息 / 判断用了哪种签名方案”，不是完整做密码学验签引擎。

**五、整体架构一句话**

```
APK(ZIP)
 ├─ AndroidManifest.xml ──► AXMLParser ──► AXMLPrinter ──► lxml
 ├─ resources.arsc     ──► ARSCParser  ──► 资源ID映射表
 └─ 签名文件            ──► asn1crypto  ──► 证书/签名方案

APK 类(core.py) 把这些结果缓存起来，暴露成：
apk.package / version_name / activities / permissions / is_signed_v2 ...
```

设计上有 3 个关键点：

1. **Orchestrator 模式**：`APK` 类只调度，不自己抠字节
2. **Lazy loading**：`resources.arsc`、V2/V3 签名第一次访问时才解析
3. **纯 Python 依赖少**：`lxml + click + asn1crypto`

**六、它和 Androguard 的区别**

| 维度       | pyaxmlparser             | Androguard               |
| ---------- | ------------------------ | ------------------------ |
| 目标       | 读 APK 元数据            | 全功能静态分析           |
| DEX 反编译 | 不解析                   | 解析类/方法/字符串       |
| 体积/速度  | 轻快                     | 重                       |
| 适合       | CI、批量扫包名/权限/签名 | 恶意代码分析、控制流分析 |

### blint

**Blint**（OWASP dep-scan 维护）是一个开源的 **Binary Linter + SBOM 生成器**，用来检查可执行文件/应用包的安全属性、能力（capabilities）、依赖组成，并生成 CycloneDX SBOM。支持 ELF / PE / Mach-O / .NET / Go / Rust，也支持 **Android APK / AAB**。

**它能对 APK 做什么**

不是传统“反编译看源码”的工具，而是偏**供应链 + 安全姿态 + 组件清单**：

- 解析 `AndroidManifest.xml`：包名、版本、权限、features
- 借助 Android SDK 的 `apkanalyzer` 提取高层元数据
- 解析 `classes.dex`：在 `--deep` 模式下分析 dex 类、SDK、tracker SDK
- 列出第三方库 / 依赖，生成 SBOM（CycloneDX）
- 分析 native 库 `.so`（架构、符号、依赖）
- 行为/能力审查：动态加载、反射、明文网络、弱加密、命令执行等
- 输出：`sbom`、`*-metadata.json`、`findings.json` 等

示例：

```bash
pip install blint

# 生成 APK 的 SBOM
blint sbom -i app.apk -o sbom.cdx.json

# 深度分析 dex / 行为
blint sbom -i app.apk -o sbom.cdx.json --deep
```

**它“能不能分析安卓组件”**

要看你说的“组件”是什么：

✅ 能：

- 权限、包名、版本
- 第三方 SDK / 库
- native 库
- 从 manifest 和 dex 推断部分组件/行为
- 安全风险、capability、tracker SDK

⚠️ 不完全像专业 APK 工具：

- 不主打把 `Activity / Service / Receiver / Provider` 完整列成树状结构
- 不如 `apkanalyzer`、`jadx`、`mobSF`、`Androguard` 那样专注 Android 组件/Intent/导出组件分析
- 如果是做**安全审计 / 恶意行为 / 导出组件 / 隐私合规**，通常配合：
  - `apkanalyzer`（官方）
  - `jadx`（反编译）
  - `MobSF`（移动安全框架）
  - `Androguard`（Python 分析）
