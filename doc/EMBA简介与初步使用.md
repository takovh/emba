---
website: https://github.com/e-m-b-a/emba
wiki: https://github.com/e-m-b-a/emba/wiki
---

嵌入式设备安全分析框架

# 一、介绍


**EMBA**（Embedded Analyzer）是一个**开源、自动化**的嵌入式设备固件安全分析框架，专门设计用于**逆向工程和安全评估**。



官方资源

- **GitHub**: [https://github.com/e-m-b-a/emba](https://github.com/e-m-b-a/emba)
- **文档**: [https://github.com/e-m-b-a/emba/wiki](https://github.com/e-m-b-a/emba/wiki)
- **Discord**: 社区交流频道

学习资源

- 官方Wiki和教程
- 示例固件和案例
- 研究论文和演讲



# 二、部署安装

从GitHub拉取代码

```sh
git clone https://github.com/e-m-b-a/emba
```

安装emba

```sh
sudo ./installer.sh -d
```

安装过程中需要拉取两个git仓库（漏洞仓库，接近4GB）和一个docker镜像（emba镜像，接近8GB）。
可将提前准备好的
- nvd-json-data-feeds.zip: nvd漏洞数据库，解压至`emba/external/`
- EPSS-data.zip: EPSS评分数据库，解压至`emba/external/`
- emba-2.0.0.tar: emba镜像，加载docker `docker load -i emba-2.0.0.tar`

```sh
git clone https://github.com/EMBA-support-repos/nvd-json-data-feeds.git
git clone https://github.com/EMBA-support-repos/EPSS-data.git
```


安装完成后需要在emba目录创建一个脚本`kill_emba`，用于终止emba进程。

```shell
#!/bin/bash -p

pgrep -f "/home/gst/emba/emba" | sudo xargs -r kill -9
```


为了让Java程序能够正常调用emba，需要做以下配置

```sh
# 执行以下命令，给emba命令添加sudo权限
sudo visudo

# 在文件末尾追加，完成后 ctrl+o 保存，回车确认， ctrl+x 退出
# gst是Linux用户名
gst ALL=(root) NOPASSWD: /home/gst/emba/emba, /home/gst/emba/kill_emba
```

完成后测试安装

```
./emba -V
```

# 三、[使用](https://github.com/e-m-b-a/emba/wiki/SBOM-environment#usage)




```bash
# -l参数指定日志目录
# -f参数指定固件目录
sudo ./emba -l ./log -f ./firmware

# -p参数指定扫描配置
sudo ./emba -l ./log -f ./firmware -p ./scan-profiles/default-scan.emba
sudo ./emba -l ./log -f ./firmware -p ./scan-profiles/quick-sbom.emba
sudo ./emba -l ./log -f ./firmware -p ./scan-profiles/default-sbom-vex.emba

sudo ./emba -l ./log -f ./firmware -m p60
sudo ./emba -l ./log -f ./firmware -p ./scan-profiles/my-sbom.emba
sudo ./emba -l ./log -f ./firmware -p ./scan-profiles/my-sbom-vex.emba

nohup sudo ./emba -l ./log -f ./firmware -p ./scan-profiles/my-sbom.emba > /dev/null 2>&1 &
```




要启动Windows可执行文件的快速SBOM生成测试，可以使用以下EMBA命令：

```
# sudo ./emba -f ~/windows_exe_file.exe -l ~/emba_logs_sbom-exe -p ./scan-profiles/quick-sbom.emba
```

对于测试基于Linux的固件镜像，具备新的SBOM功能和二进制分析机制，可以使用以下扫描配置文件：

```
# sudo ./emba -f ~/firmware.bin -l ~/emba_logs_sbom-firmware -p ./scan-profiles/default-sbom.emba
```

一般应使用以下扫描配置文件：

- 仅使用最小/非二元SBOM生成机制时，应使用_quick-sbom.emba_扫描配置文件
- 要使用完整的SBOM功能（包括二进制测试），应使用_default-sbom.emba_扫描配置文件
- 要进行具备完整SBOM功能的固件分析，应使用 _default-scan.emba_ 扫描配置文件
- 有时候（比如你测试一些zip/tgz/打包文件系统/源码），禁用深度解压机制是合理的。这可以通过扫描配置文件或 _EMBA_ 参数完成`DISABLE_DEEP=0` `-q`



# 总结


## 源码

### 启动


`emba`.main()
- import_helper()
- `helpers_emba_defaults`.set_defaults()【各种默认配置】
- import_module()【导入模块】
- `helpers_emba_parameter_parser`.emba_parameter_parsing()【解析命令行参数】
- `helpers_emba_defaults`.set_log_paths()【模块日志路径】
- `helpers_emba_dependency_check`.dependency_check()【模块依赖】
- run_modules()【运行模块】


### profile

- SILENT=1会调用initial_status_bar
- DISABLE_STATUS_BAR=0会调用remove_status_bar




emba源码

```sh
# if [[ ${USE_DOCKER} -eq 1 ]] ; then
if [[ "${IN_DOCKER}" -eq 0 ]] && [[ "${SILENT}" -eq 1 ]]; then
  initial_status_bar &
  # Trap the window resize signal (handle window resize events).
  trap 'initial_status_bar' WINCH
fi

# F 模块运行完成后
[[ ${DISABLE_STATUS_BAR} -eq 0 ]] && remove_status_bar
```

### mapfile

mapfile 是 Bash 内置命令（Bash 4.0+），将标准输入按行读入数组。-t 移除每行末尾的换行符。

```bash
# 这行等价于：
# while IFS= read -r line; do
#   lAPK_MGMT_STATUS_ARR+=("$line")
# done < <(grep "apk/db/installed" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)
# 即：从 P99_CSV_LOG 中过滤出包含 apk/db/installed 的行，取分号分隔的第二列，去重排序后存入数组 lAPK_MGMT_STATUS_ARR。
mapfile -t lAPK_MGMT_STATUS_ARR < <(grep "apk/db/installed" "${P99_CSV_LOG}" | cut -d ';' -f2 | sort -u || true)

# 从 P99_CSV_LOG 中过滤出包含 .apk 的行，取分号分隔的第二列，去重排序后存入数组 lAPK_ARCHIVES_ARR。
mapfile -t lAPK_ARCHIVES_ARR < <(grep "\.apk;" "${P99_CSV_LOG}" | cut -d ';' -f2 || true)
```


命令解释

- `grep "apk/db/installed" "${P99_CSV_LOG}"`: 从 P99_CSV_LOG 中过滤出包含 apk/db/installed 的行
- `cut -d ';' -f2`:  取分号分隔的第二列
- `sort -u`: 去重排序
- `|| true`: 避免 set -e（严格模式）下 grep 或 sort -u 因无匹配行而返回非零退出码，导致整个脚本中止。
- `<(...)`: **进程替换** — 将括号内命令的输出虚拟成一个"文件"（实为 /dev/fd/* 文件描述符）
- `... < <(...)`: **输入重定向** — 把右边的"文件"重定向为标准输入
- `mapfile -t 数组 标准输入`: 将标准输入按行读入数组。-t 移除每行末尾的换行符

> 为什么不用管道？ 管道 cmd | mapfile 会在子 shell 里执行，管道结束后数组不可见；而进程替换在当前 shell 执行，数组值可以保留。

## external 目录

可以通过`docker-compose.yml`文件配置external映射

docker内的external目录有以下文件：

```
drwxr-xr-x  1 root      root          4096 Jun  4 12:59 .
drwxr-xr-x  1 root      root          4096 Jun  4 12:59 ..
drwxr-xr-x  3 root      root          4096 Dec 16 02:20 APKHunt
drwxr-xr-x  3 root      root          4096 Dec 16 02:19 BGScriptTool
drwxr-xr-x  4 root      root          4096 Dec 16 02:19 BIOSUtilities
drwxr-xr-x 11 root      root          4096 Dec 16 02:28 EMBA_Live_bins
drwxr-xr-x  2 root      root          4096 Dec 16 02:12 UEFITool
drwxr-xr-x 11 root      root          4096 Dec 16 02:15 binwalk
-rwxr-xr-x  1 root      root         23384 Dec 16 02:12 buffalo-enc.elf
-rwxr-xr-x  1 root      root      46881344 Jun  7  2025 capa
-rwxr-xr-x  1 root      root         75646 Dec 16 02:24 checksec
drwxr-xr-x  3 root      root          4096 Dec 16 02:30 chrome-headless-shell
drwxr-xr-x  6 root      root          4096 Dec 16 02:16 cpu_rec
drwxr-xr-x 16 root      root          4096 Dec 16 03:17 cve-bin-tool
drwxr-xr-x 13 root      root          4096 Dec 16 02:26 cwe_checker
drwxr-xr-x  8 root      root          4096 Dec 16 02:12 dji-firmware-tools
drwxr-xr-x  8 root      root          4096 Dec 16 03:47 emba_venv
-rwxr-xr-x  1 root      root           637 Dec 16 02:24 engenius-decrypt.py
-rw-rw-r--  1 linuxbrew linuxbrew     5831 Jun  4 11:41 extract_yaffs_final.py
drwxr-xr-x  7 root      root          4096 Dec 16 02:19 fwhunt-scan
drwxr-xr-x  3 root      root          4096 Dec 16 02:25 ghidra
drwxr-xr-x  2 root      root          4096 Dec 16 02:25 ghidra_scripts
drwxr-xr-x  3 root      root          4096 Dec 16 02:23 iniscan
drwxr-xr-x  5 root      root          4096 Dec 16 02:24 jchroot
drwxr-xr-x  8 root      root          4096 Dec 16 02:23 kconfig-hardened-check
-rwxr-xr-x  1 root      root         90858 Dec 16 02:24 linux-exploit-suggester.sh
drwxr-xr-x  2 root      root          4096 Jan  8 12:39 linux_kernel_sources
drwxr-xr-x  7 root      root          4096 Dec 16 02:29 nikto
drwxrwxr-x 34 linuxbrew linuxbrew     4096 Jan  8 10:02 nvd-json-data-feeds
-rwxr-xr-x  1 root      root      65510976 Dec 16 01:37 objdump
drwxr-xr-x  5 root      root          4096 Dec 16 02:12 payload_dumper
-rwxr-xr-x  1 root      root          2766 Dec 16 02:24 pixd_png.py
-rwxr-xr-x  1 root      root         18528 Dec 16 02:24 pixde
-rwxr-xr-x  1 root      root       3155849 Jan 12  2023 progpilot
drwxr-xr-x 16 root      root          4096 Dec 16 02:10 radare2
drwxr-xr-x 16 root      root          4096 Dec 16 02:17 rizin
drwxr-xr-x 35 root      root          4096 Dec 16 02:21 semgrep-rules
drwxr-xr-x  6 root      root          4096 Dec 16 02:21 semgrep-rules-0xdea
drwxr-xr-x  3 root      root          4096 Dec 16 02:12 smcbmc
-rwxr-xr-x  1 root      root          1947 Dec 16 02:24 sshdcc
drwxr-xr-x  8 root      root          4096 Dec 16 02:24 stacs-rules
-rwxr-xr-x  1 root      root         16229 Dec 16 02:24 sudo-parser.pl
drwxr-xr-x  9 root      root          4096 Dec 16 02:29 testssl.sh
drwxr-xr-x 10 root      root          4096 Dec 16 02:14 unblob
-rwxr-xr-x  1 root      root       1856529 Nov  5  2025 vineflower-1.11.2.jar
drwxr-xr-x  5 root      root          4096 Dec 16 02:23 vmlinux-to-elf
drwxr-xr-x  2 root      root          4096 Dec 16 02:24 yara
drwxr-xr-x  6 root      root          4096 Dec 16 02:21 zarn
```


## 日志


使用`default-scan.emba`
```
[*] Tue Jan 13 18:29:14 CST 2026 - P02_firmware_bin_file_check starting
[*] Tue Jan 13 18:29:15 CST 2026 - Q02_openai_question starting
[*] Tue Jan 13 18:29:19 CST 2026 - Q02_openai_question finished
[*] Tue Jan 13 18:29:20 CST 2026 - Quest container finished
[*] Tue Jan 13 18:29:25 CST 2026 - P02_firmware_bin_file_check finished
[*] Tue Jan 13 18:29:29 CST 2026 - P50_binwalk_extractor starting
[*] Tue Jan 13 18:29:32 CST 2026 - P50_binwalk_extractor finished
[*] Tue Jan 13 18:29:32 CST 2026 - P55_unblob_extractor starting
[*] Tue Jan 13 18:29:35 CST 2026 - P55_unblob_extractor finished
[*] Tue Jan 13 18:29:37 CST 2026 - P60_deep_extractor starting
[*] Tue Jan 13 18:46:45 CST 2026 - P60_deep_extractor finished
[*] Tue Jan 13 18:46:46 CST 2026 - P65_package_extractor starting
[*] Tue Jan 13 18:46:56 CST 2026 - P65_package_extractor finished
[*] Tue Jan 13 18:46:56 CST 2026 - P99_prepare_analyzer starting
[*] Tue Jan 13 18:47:06 CST 2026 - P99_prepare_analyzer finished
[*] Tue Jan 13 18:47:15 CST 2026 - S26_kernel_vuln_verifier starting
[*] Tue Jan 13 18:47:16 CST 2026 - S24_kernel_bin_identifier starting
[*] Tue Jan 13 18:47:16 CST 2026 - S12_binary_protection starting
[*] Tue Jan 13 18:47:17 CST 2026 - S09_firmware_base_version_check starting
[*] Tue Jan 13 18:47:18 CST 2026 - S02_uefi_fwhunt starting
[*] Tue Jan 13 18:47:19 CST 2026 - S03_firmware_bin_base_analyzer starting
[*] Tue Jan 13 18:47:40 CST 2026 - S02_UEFI_FwHunt finished
[*] Tue Jan 13 18:48:10 CST 2026 - S04_windows_basic_analysis starting
[*] Tue Jan 13 18:48:48 CST 2026 - S04_windows_basic_analysis finished
[*] Tue Jan 13 18:49:10 CST 2026 - S05_firmware_details starting
[*] Tue Jan 13 18:53:48 CST 2026 - S05_firmware_details finished
[*] Tue Jan 13 18:54:13 CST 2026 - S06_distribution_identification starting
[*] Tue Jan 13 19:01:44 CST 2026 - S06_distribution_identification finished
[*] Tue Jan 13 19:02:04 CST 2026 - S07_bootloader_check starting
[*] Tue Jan 13 19:08:34 CST 2026 - S07_bootloader_check finished
[*] Tue Jan 13 19:09:07 CST 2026 - S08_main_package_sbom starting
[*] Tue Jan 13 19:10:12 CST 2026 - S03_firmware_bin_base_analyzer finished
[*] Tue Jan 13 19:10:45 CST 2026 - S13_weak_func_check starting
[*] Tue Jan 13 19:40:17 CST 2026 - S24_kernel_bin_identifier finished
[*] Tue Jan 13 19:40:30 CST 2026 - S14_weak_func_radare_check starting
[*] Tue Jan 13 19:40:37 CST 2026 - S26_kernel_vuln_verifier finished
[*] Tue Jan 13 19:40:48 CST 2026 - S16_ghidra_decompile_checks starting
[*] Tue Jan 13 20:01:42 CST 2026 - S09_firmware_base_version_check finished
[*] Tue Jan 13 20:01:46 CST 2026 - S17_cwe_checker starting
[*] Tue Jan 13 20:06:28 CST 2026 - S12_binary_protection finished
[*] Tue Jan 13 20:06:33 CST 2026 - S18_capa_checker starting
[*] Tue Jan 13 20:09:29 CST 2026 - S18_capa_checker finished
[*] Tue Jan 13 20:09:43 CST 2026 - S19_apk_check starting
[*] Tue Jan 13 20:10:11 CST 2026 - S19_apk_check finished
[*] Tue Jan 13 20:10:24 CST 2026 - S20_shell_check starting
[*] Tue Jan 13 21:59:07 CST 2026 - S20_shell_check finished
[*] Tue Jan 13 21:59:17 CST 2026 - S21_python_check starting
[*] Tue Jan 13 22:00:20 CST 2026 - S21_python_check finished
[*] Tue Jan 13 22:00:29 CST 2026 - S22_php_check starting
[*] Tue Jan 13 22:22:13 CST 2026 - S22_php_check finished
[*] Tue Jan 13 22:22:26 CST 2026 - S23_lua_check starting
[*] Tue Jan 13 22:57:11 CST 2026 - S23_lua_check finished
[*] Tue Jan 13 22:57:24 CST 2026 - S25_kernel_check starting
[*] Tue Jan 13 23:50:46 CST 2026 - S25_kernel_check finished
[*] Tue Jan 13 23:50:53 CST 2026 - S27_perl_check starting
[*] Tue Jan 13 23:51:14 CST 2026 - S27_perl_check finished
[*] Tue Jan 13 23:51:22 CST 2026 - S28_java_check starting
[*] Tue Jan 13 23:51:38 CST 2026 - S28_java_check finished
[*] Tue Jan 13 23:51:47 CST 2026 - S35_http_file_check starting
[*] Wed Jan 14 00:03:45 CST 2026 - S35_http_file_check finished
[*] Wed Jan 14 00:03:52 CST 2026 - S36_lighttpd starting
[*] Wed Jan 14 00:04:30 CST 2026 - S36_lighttpd finished
[*] Wed Jan 14 00:04:40 CST 2026 - S40_weak_perm_check starting
[*] Wed Jan 14 00:06:04 CST 2026 - S40_weak_perm_check finished
[*] Wed Jan 14 00:06:17 CST 2026 - S45_pass_file_check starting
[*] Wed Jan 14 00:09:57 CST 2026 - S45_pass_file_check finished
[*] Wed Jan 14 00:10:08 CST 2026 - S50_authentication_check starting
[*] Wed Jan 14 00:15:07 CST 2026 - S50_authentication_check finished
[*] Wed Jan 14 00:15:20 CST 2026 - S55_history_file_check starting
[*] Wed Jan 14 00:16:00 CST 2026 - S55_history_file_check finished
[*] Wed Jan 14 00:16:11 CST 2026 - S60_cert_file_check starting
[*] Wed Jan 14 01:54:52 CST 2026 - S60_cert_file_check finished
[*] Wed Jan 14 01:55:02 CST 2026 - S65_config_file_check starting
[*] Wed Jan 14 02:01:23 CST 2026 - S65_config_file_check finished
[*] Wed Jan 14 02:01:33 CST 2026 - S75_network_check starting
[*] Wed Jan 14 02:02:17 CST 2026 - S75_network_check finished
[*] Wed Jan 14 02:02:25 CST 2026 - S80_cronjob_check starting
[*] Wed Jan 14 02:02:45 CST 2026 - S80_cronjob_check finished
[*] Wed Jan 14 02:02:54 CST 2026 - S85_ssh_check starting
[*] Wed Jan 14 02:03:49 CST 2026 - S85_ssh_check finished
[*] Wed Jan 14 02:04:01 CST 2026 - S90_mail_check starting
[*] Wed Jan 14 02:04:22 CST 2026 - S90_mail_check finished
[*] Wed Jan 14 02:04:30 CST 2026 - S95_interesting_files_check starting
[*] Wed Jan 14 02:07:11 CST 2026 - S95_interesting_files_check finished
[*] Wed Jan 14 02:07:32 CST 2026 - S100_command_inj_check starting
[*] Wed Jan 14 02:43:45 CST 2026 - S100_command_inj_check finished
[*] Wed Jan 14 02:43:53 CST 2026 - S106_deep_key_search starting
[*] Wed Jan 14 02:47:49 CST 2026 - S106_deep_key_search finished
[*] Wed Jan 14 02:47:53 CST 2026 - S107_deep_password_search starting
[*] Wed Jan 14 02:53:23 CST 2026 - S107_deep_password_search finished
[*] Wed Jan 14 02:53:25 CST 2026 - S108_stacs_password_search starting
[*] Wed Jan 14 03:00:20 CST 2026 - S108_stacs_password_search finished
[*] Wed Jan 14 03:00:27 CST 2026 - S109_jtr_local_pw_cracking starting
[*] Wed Jan 14 04:01:41 CST 2026 - S13_weak_func_check finished
[*] Wed Jan 14 04:01:47 CST 2026 - S115_usermode_emulator starting
[*] Wed Jan 14 05:39:07 CST 2026 - S109_jtr_local_pw_cracking finished
[*] Wed Jan 14 05:39:27 CST 2026 - S116_qemu_version_detection starting
[*] Wed Jan 14 05:58:45 CST 2026 - S08_main_package_sbom finished
[*] Wed Jan 14 05:59:05 CST 2026 - S118_busybox_verifier starting
[*] Wed Jan 14 07:57:21 CST 2026 - S14_weak_func_radare_check finished
[*] Wed Jan 14 07:59:33 CST 2026 - S17_cwe_checker finished
[*] Wed Jan 14 09:22:37 CST 2026 - S115_usermode_emulator finished
[*] Wed Jan 14 10:04:52 CST 2026 - S116_qemu_version_detection finished
[*] Wed Jan 14 10:05:03 CST 2026 - S118_busybox_verifier finished
[*] Wed Jan 14 17:48:59 CST 2026 - S16_ghidra_decompile_checks finished
[*] Wed Jan 14 17:49:01 CST 2026 - F02_toolchain starting
[*] Wed Jan 14 17:49:17 CST 2026 - F02_toolchain finished
[*] Wed Jan 14 17:49:17 CST 2026 - F05_qs_resolver starting
[*] Wed Jan 14 17:57:52 CST 2026 - F05_qs_resolver finished
[*] Wed Jan 14 17:57:53 CST 2026 - F10_license_summary starting
[*] Wed Jan 14 18:03:56 CST 2026 - F10_license_summary finished
[*] Wed Jan 14 18:03:57 CST 2026 - F14_tag_builder starting
[*] Wed Jan 14 18:04:05 CST 2026 - F14_tag_builder finished
[*] Wed Jan 14 18:04:06 CST 2026 - F15_cyclonedx_sbom starting
[*] Wed Jan 14 18:08:01 CST 2026 - F15_cyclonedx_sbom finished
[*] Wed Jan 14 18:08:01 CST 2026 - F17_cve_bin_tool starting
```


# 工作

p99_prepare_analyzer 中记录所有文件及其`file`命令的结果

```bash
# 查看所有的apk文件
grep -P '.apk;' csv_logs/p99_prepare_analyzer.csv
grep -P '.apk;' csv_logs/p99_prepare_analyzer.csv | cut -d ';' -f2
```

