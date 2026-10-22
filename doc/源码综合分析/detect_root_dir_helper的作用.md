### 判定流程

`detect_root_dir_helper()` 的逻辑是：**通过多种特征收集所有候选根目录，合并去重后写入 `ROOT_PATH`；有候选就设 `RTOS=0`，全部未命中则回退到搜索目录并设 `RTOS=1`。** 各机制会累加结果，命中一种后仍会继续执行后面的机制。

实现入口：[helpers\_emba\_prepare.sh:617](/home/tako/workspace/emba/helpers/helpers_emba_prepare.sh:617)。

**1. 初始化与前置检查**

* 第一个参数是搜索路径 `lSEARCH_PATH`。
* 每次调用首先清空全局数组 `ROOT_PATH`，不会保留上次检测结果。
* 必须存在 `${P99_CSV_LOG}`，否则直接 `return`。

这里有个容易忽略的细节：**CSV 不存在时，连目录结构检测和兜底都不会执行**，此时 `ROOT_PATH` 已清空，`RTOS` 保持原值。

CSV 中主要使用第 2 列（文件路径）和第 8 列（`file -b` 的类型描述）。

**2. ELF 解释器反推根目录**

仅在 `SBOM_MINIMAL=0` 时执行。[源码位置](/home/tako/workspace/emba/helpers/helpers_emba_prepare.sh:636)

过程如下：

1. 从 CSV 筛选搜索路径下带有 `ELF` 的记录。
2. 读取第 8 列，提取 `interpreter /...` 中的解释器绝对路径，并去重。
3. 在 CSV 第 2 列中查找包含该解释器路径的文件路径。
4. 从实际路径中移除解释器路径，得到候选根目录。
5. 候选必须真实存在且是目录；以 `/lib/` 结尾的候选被视为常见误报而跳过。

例如：

```text
ELF 声明的解释器： /lib/ld-uClibc.so.0
CSV 中的实际路径： /logs/firmware/rootfs/lib/ld-uClibc.so.0
反推候选根目录：   /logs/firmware/rootfs
```

命中后记录机制为 `binary interpreter`。

注意：第 3 步查的是**整个 CSV**，没有再次限定 `lSEARCH_PATH`；而且使用的是包含匹配，并非严格的路径后缀匹配。

**3. BusyBox 与 Shell 路径反推**

同样仅在 `SBOM_MINIMAL=0` 时执行，依次检查：

| 特征      | 筛选方式                          | 反推方式                                         |
| ------- | ----------------------------- | -------------------------------------------- |
| BusyBox | 搜索路径下的 ELF 记录包含 `bin/busybox` | 移除匹配的 `/bin/busybox...` 或 `/sbin/busybox...` |
| Bash    | 搜索路径下的 ELF 记录包含 `bin/bash`    | 移除匹配的 `/bin/bash...` 或 `/sbin/bash...`       |
| sh      | 搜索路径下的 ELF 记录包含 `bin/sh;`     | 移除匹配的 `/bin/sh...` 或 `/sbin/sh...`           |

反推后只检查候选是否为现存目录，满足就加入 `ROOT_PATH`，**不要求再具备 5 个标准目录**。[源码位置](/home/tako/workspace/emba/helpers/helpers_emba_prepare.sh:662)

例如：

```text
/logs/firmware/rootfs/bin/busybox → /logs/firmware/rootfs
```

这里依据的是 CSV 中带 `ELF` 的记录，因此不能简单理解为“只要存在一个名叫 `bin/sh` 的文件或符号链接就能命中”。

**4. 标准目录结构检测**

只要通过了前面的 CSV 存在性检查，这一步都会执行，包括 `SBOM_MINIMAL=1` 的情况。[源码位置](/home/tako/workspace/emba/helpers/helpers_emba_prepare.sh:699)

使用 `find "${lSEARCH_PATH}" -xdev` 搜索以下名称：

```text
sbin  bin  lib  etc  root  dev  opt  proc  lib64  boot  home
```

对每个匹配项取 `dirname`，按父目录分组计数。**同一个父目录下命中至少 5 项**，且该父目录存在，就加入候选。

例如：

```text
rootfs/bin
rootfs/sbin
rootfs/lib
rootfs/etc
rootfs/dev
```

这 5 项的父目录都是 `rootfs`，所以接受 `rootfs`。

具体边界：

* 统计的是同一父目录下的匹配项，不是整个子树累计。
* `usr`、`var`、`tmp`、`mnt` 不在本函数的名单中。
* `-xdev` 限制跨文件系统递归。
* `find` 没有加 `-type d`，所以这些名称对应的普通文件、符号链接也可能参与计数；最后检查的是它们的父目录。

**5. 设置全局结果并去重**

[源码位置](/home/tako/workspace/emba/helpers/helpers_emba_prepare.sh:723)

| 检测结果   | `ROOT_PATH`           | `RTOS` |
| ------ | --------------------- | ------ |
| 至少一个候选 | 保留全部候选，`sort -u` 去重排序 | `0`    |
| 没有候选   | 放入 `lSEARCH_PATH` 自身  | `1`    |

因此，`RTOS=1` 在这里表达的是\*\*“这些启发式规则没有识别到 Linux 根目录”\*\*，并不构成对真实 RTOS 类型的确认。

另外，日志里的 `via binary interpreter / busybox / shell / dir names` 是本次调用累计的机制字符串，**没有记录每个候选各自命中了哪种机制**。多个根目录可能打印相同的 `via` 内容。

调用层面，P99 只在 `SBOM_MINIMAL!=1`、`UEFI_VERIFIED!=1` 且 `ROOT_PATH` 为空时调用它；传入的第二个参数 `"main"` 在该函数内没有被读取。[调用位置](/home/tako/workspace/emba/modules/P99_prepare_analyzer.sh:77)

### 调用时机

它会在**提取过程中多次调用**，还会在差异分析、用户态仿真时调用。当前代码共有 **23 个调用点，分布在 11 个模块中**；一次扫描只会执行条件满足的那些调用点。

| 模块                                                                                           | 调用时机                                                          | 检测范围                                          |
|:--------------------------------------------------------------------------------------------:|:-------------------------------------------------------------:|:---------------------------------------------:|
| [P16 YAFFS1 (line 95)](/home/tako/workspace/emba/modules/P16_yaffs1_extractor.sh:95)         | 提取完成、文件索引生成并等待完成后                                             | 本次提取目录                                        |
| [P18 BMC (line 82)](/home/tako/workspace/emba/modules/P18_BMC_decryptor.sh:82)               | 解密提取、文件索引生成并等待完成后                                             | 本次提取目录                                        |
| [P19 UFS (line 88)](/home/tako/workspace/emba/modules/P19_bsd_ufs_mounter.sh:88)             | 挂载内容提取、文件索引生成、卸载临时挂载后                                         | 本次提取目录                                        |
| [P35 UEFI (line 34)](/home/tako/workspace/emba/modules/P35_UEFI_extractor.sh:34)             | 入口发现当前输入是目录时；Unblob 提取后；Binwalk 提取后                           | 当前固件目录或对应提取目录                                 |
| [P40 DJI (line 120)](/home/tako/workspace/emba/modules/P40_DJI_extractor.sh:120)             | 初次 Unblob 提取后；内部处理循环中；XV4 提取后                                 | 对应提取目录，或整个 `${LOG_DIR}/firmware`              |
| [P50 Binwalk (line 29)](/home/tako/workspace/emba/modules/P50_binwalk_extractor.sh:29)       | 入口发现输入为目录且 `RTOS=1` 时；走到提取流程末尾时                               | 当前固件目录或 Binwalk 输出目录                          |
| [P55 Unblob (line 34)](/home/tako/workspace/emba/modules/P55_unblob_extractor.sh:34)         | 通过前置跳过条件后，输入为目录且 `RTOS=1` 时；Unblob 流程后；全系统仿真模式的 Binwalk 恢复提取后 | 对应目录                                          |
| [P60 深度提取 (line 132)](/home/tako/workspace/emba/modules/P60_deep_extractor.sh:132)           | 缺少 CSV、补建索引后；每轮深度提取结束后，最多 4 轮                                 | `${LOG_DIR}/firmware` 或 `${FIRMWARE_PATH_CP}` |
| [P99 分析准备 (line 77)](/home/tako/workspace/emba/modules/P99_prepare_analyzer.sh:77)           | 非最小 SBOM 模式、未验证为 UEFI，且 `ROOT_PATH` 为空时                       | `${FIRMWARE_PATH}`                            |
| [D05 差异提取 (line 69)](/home/tako/workspace/emba/modules/D05_firmware_diffing_extractor.sh:69) | 两个固件分别提取后，输出目录存在时，各调用一次                                       | 两个固件各自的提取目录                                   |
| [S115 用户态仿真 (line 71)](/home/tako/workspace/emba/modules/S115_usermode_emulator.sh:71)       | `QEMULATION=1`且 `RTOS=0`，完成 `copy_firmware`后                  | 仿真工作副本 `${EMULATION_PATH_BASE}`               |

这些调用主要承担三种用途：

* **提取前确认**：现有目录是否已经包含 Linux 根文件系统，若已找到，就跳过后续提取。
* **提取后确认**：本轮是否解出了根文件系统，决定是否继续下一种提取方式或下一轮深度提取。
* **切换检测对象**：例如 D05 从固件 1 切换到固件 2，S115 从原始提取目录切换到仿真副本。

与你选中的“清空 `ROOT_PATH`”直接相关的是：**每次调用都会替换当前进程中的检测结果，不会把历次调用发现的根目录累积起来。** 因而需要区分“本次提取目录”和“整个固件目录”这两种检测范围。
另外，**P99 不是无条件的最终全量重检**：只要 `ROOT_PATH` 非空，它就不再调用。即使数组中只有上次失败时放入的兜底搜索路径，也会因此跳过。

### Android 多分区场景

**这套规则可以发现 Android 中具有 Linux 特征的目录树，但不能据此判断整个 Android 固件是否已完整解包。** 问题不在于 `ROOT_PATH` 只能保存一个目录，而在于任意一个候选命中后，都会把全局 `RTOS` 设为 `0`，进而影响后续提取。

#### 分区根目录与运行时根目录

Android 的 `system`、`vendor`、`product`、`system_ext`、`odm` 等分区承载不同内容；动态分区方案还可以把多个逻辑分区放在 `super` 中。各分区的目录树通过挂载关系参与组成设备运行时的文件系统视图，不能把某一个分区的提取目录直接视为完整的设备 `/`。参见 [AOSP 分区说明](https://source.android.google.cn/docs/core/architecture/partitions?hl=en) 和 [动态分区说明](https://source.android.google.cn/docs/core/ota/dynamic_partitions?hl=en)。

对 `detect_root_dir_helper()` 而言，它看到的只是提取后的路径和文件索引，不会解析 Android 分区的挂载关系。因此需要区分：

| 概念 | 含义 | 当前函数是否识别 |
| --- | --- | --- |
| 分区文件系统根目录 | 单个分区展开后目录树的起点 | 仅在命中通用启发式规则时加入候选 |
| 设备运行时的 `/` | 多个分区按挂载关系组合后的视图 | 不负责重建 |
| 固件提取完成 | 输入范围内需要分析的分区已处理，剩余失败或不支持项已有记录 | 不负责验证 |

#### 多个分区可能命中，也可能漏检

函数没有 Android 分区白名单，也不要求候选必须包含完整的 Linux 目录结构。每个已展开的分区只要命中任意一种机制，就可能被加入 `ROOT_PATH`。

| 分区提取后的特征 | 当前判定行为 |
| --- | --- |
| 存在被索引为 ELF 的 `bin/sh` | 可通过 Shell 路径反推出候选，不需要满足 5 项目录特征 |
| ELF 声明的解释器能在索引中找到对应实际路径 | 可通过解释器路径反推候选；实际结果取决于镜像提取后的路径布局 |
| 同一父目录下命中 `bin`、`lib`、`lib64`、`etc`、`sbin` 等至少 5 个指定名称 | 可通过目录结构规则成为候选 |
| 主要包含应用、资源或少量库，缺少上述特征 | 即使分区已成功展开，也可能不进入 `ROOT_PATH` |

因此，**多个 Android 分区可以同时被识别为多个候选，但并非每个分区都会被识别**。候选数量既不是分区总数，也不能作为提取完整度指标。

另外，解释器查找的第二步使用整个 CSV，而不是严格限制在当前分区内；候选之间也没有记录分区归属、挂载点或 A/B 槽位。不能仅凭 `ROOT_PATH` 数组还原 Android 的分区关系。

#### 修改前：对 P60 停止条件的影响

[P60 入口](/home/tako/workspace/emba/modules/P60_deep_extractor.sh:33) 在 `RTOS=0` 时直接跳过深度提取；[每轮深度提取](/home/tako/workspace/emba/modules/P60_deep_extractor.sh:140) 也要求 `RTOS=1`，并在轮末调用 `detect_root_dir_helper()` 更新判定。

以下是一个可能提前停止的状态示例，不代表所有 Android 固件都会出现：

```text
firmware/
├── system_extracted/   ← 已展开，且命中根目录规则
├── vendor.img          ← 尚未展开
└── product.img         ← 尚未展开

detect_root_dir_helper()
  → ROOT_PATH 包含 system_extracted
  → RTOS=0
  → P60 入口跳过，或后续深度提取轮次跳过
```

这里实际证明的只是“发现了至少一个 Linux 根目录候选”，不能推出“其他分区都已处理”。若未展开镜像不再由其他提取流程处理，后续文件级分析和 SBOM 收集就可能遗漏这些分区中的内容。

需要注意轮次边界：`deeper_extractor_helper()` 会等待本轮所有已调度任务完成，再返回执行根目录检测。**某个分区先成功，不会通过这个轮末判定中断同轮其他任务**；风险主要在进入 P60 前已经 `RTOS=0`，或者某轮新产生了需要下一轮继续处理的镜像，却因发现候选而停止。

#### 当前 Android 提取链的阶段区别

当前工作区中的 Android 提取模块分别处理不同层次：

| 阶段 | 模块或函数 | 产物与边界 |
| --- | --- | --- |
| OTA 容器提取 | [P25 / android_ota_extractor()](/home/tako/workspace/emba/modules/P25_android_ota.sh:40) | 调用 payload dumper，生成后续待处理的分区镜像并建立索引 |
| Sparse 转换、super 拆分 | [P26 / android_image_extractor()](/home/tako/workspace/emba/modules/P26_android_sparse_super.sh:70) | 将 sparse 转为原始镜像；若是 super，则拆出具名逻辑分区镜像并建立索引 |
| 分区文件系统提取 | [P60 / deeper_extractor_threader()](/home/tako/workspace/emba/modules/P60_deep_extractor.sh:196) 中的专用提取器或通用提取器 | 继续处理分区镜像，目标是取得可供分析的文件；实际效果取决于格式及工具支持 |
| 根目录候选识别 | `detect_root_dir_helper()` | 检测已展开的目录树，更新 `ROOT_PATH` 和 `RTOS` |

**从 OTA 或 super 中拆出了分区镜像，不等于已经展开了这些分区的文件系统。** 当前 P26 也不承担 Android 挂载视图重建或所有分区提取完成的确认。

#### 更适合 Android 的判定方向

以下属于改进建议，当前代码尚未实现：

1. **按镜像或分区维护提取状态**：记录输入来源、分区名、槽位（适用时）、输出目录，以及待处理、成功、失败、不支持等状态。成功与否应根据文件系统提取结果判断，不能要求每个分区都命中根目录规则。
2. **独立判断是否继续提取**：有未处理镜像或本轮新产生的可提取对象时继续；队列处理完毕或不再产生新的可提取对象时结束，同时保留深度、空间和去重限制。失败及不支持项应单独报告。
3. **保留 `RTOS` 和 `ROOT_PATH` 的识别用途**：`RTOS=0` 表示发现 Linux 特征，`ROOT_PATH` 保存候选；二者不再单独充当 Android 提取完成的依据。
4. **按整体范围汇总结果**：完成分区处理后，对整体输出重检候选，或按分区维护结果再汇总，避免局部调用清空并覆盖其他分区的候选。需要运行时路径解析或仿真时，再依据分区元数据和挂载配置建立视图。

仅增加 `DEEP_EXT_DEPTH` 无法解决原有问题：只要 `RTOS=0` 的入口与轮次条件仍然存在，提高深度也不会让被跳过的轮次执行。


#### 当前修改：P60 不再按 RTOS 提前停止

P60 已移除入口、补建 CSV 后以及四轮提取条件中的 `RTOS` 判断。无论是否已经检测到 Linux 根目录，均按原有深度和磁盘限制执行后续提取轮次，不再区分 Android 与其他固件。`detect_root_dir_helper()` 仍在补建索引后及每轮提取后更新 `ROOT_PATH` 和 `RTOS`，供后续分析使用。

保留原有 UEFI/DJI 跳过条件、`DISABLE_DEEP`、`DEEP_EXT_DEPTH`、磁盘限制、文件候选来源和 MD5 去重。此次修改不引入 Android 专用模式、标记文件或新的文件枚举机制，也不涉及 EXT 提取器。
