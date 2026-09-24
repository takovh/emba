
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
