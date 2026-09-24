## `P65_package_extractor`

P65_package_extractor.sh 是一个软件包归档提取模块，负责从固件中识别并解包常见的软件包格式。

主要功能

它依次调用四个子提取器，每次提取前都会检查磁盘空间是否充足：

| 子函数             | 格式                     | 工具                 |
| --------------- | ---------------------- | ------------------ |
| deb_extractor() | .deb / .udeb（Debian 包） | dpkg-deb --extract |
| ipk_extractor() | .ipk（OpenWrt 包）        | tar + cpio         |
| apk_extractor() | .apk（Android 包）        | unzip              |
| rpm_extractor() | .rpm（Red Hat 包）        | rpm2cpio + cpio    |

工作流程

1. 记录提取前的文件数量（FILES_PRE_PACKAGE）
2. 按顺序运行四个子提取器（遇到磁盘空间不足则跳过后续）
3. 所有包都解压到 ROOT_PATH 指定的根目录
4. 提取完成后统计新增文件数，若有新文件则：
  - 调用 binary_architecture_threader() 分析新提取的 ELF 二进制架构
  - 运行 linux_basic_identification() 识别 Linux 路径结构
  - 打印提取前后的文件数对比

设计特点

- deb_extractor 支持多线程（通过 THREADED 标志和 WAIT_PIDS_P20）
- 使用 md5sum 去重（sort -u -k1,1 | cut -d\ -f3）避免重复提取相同内容的包
- 设置 DISABLE_DEEP=1 时整个模块直接跳过

简而言之：它把固件中散落的各类 Linux 发行版软件包解压到根文件系统目录，让后续的静态分析模块（S 系列）能看到完整的文件内容。
  