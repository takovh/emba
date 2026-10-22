# 安卓

P02_firmware_bin_file_check
P16_yaffs1_extractor
P50_binwalk_extractor
P55_unblob_extractor
P60_deep_extractor
P65_package_extractor
P99_prepare_analyzer
S06_distribution_identification
S08_main_package_sbom
S09_firmware_base_version_check
S24_kernel_bin_identifier
S25_kernel_check
F14_tag_builder
F15_cyclonedx_sbom

## 需求问题

- 扫描结果应该包含哪些组成部分（BOM组件）？
  - 【Linux部分】
  - 【安卓Framework部分】
  - 【apk】
  - 【apk依赖的组件】
- 多个apk有相同的组件时如何处理

## 源码问题

- 安卓固件解包后多个目录结构如何组织
- P模块的extractor解包到哪一步

# RTOS
