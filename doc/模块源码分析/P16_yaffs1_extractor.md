## `P16_yaffs1_extractor`

如果 `P02_firmware_bin_file_check` 检测到 YAFFS v1 文件系统，EMBA 会调用该模块进行解包。模块使用 `extract_yaffs1.py` 解析小端、无 OOB 数据的 YAFFS1 镜像，将文件、目录和符号链接恢复到 `${LOG_DIR}/firmware/yaffs1_extracted/`。

提取完成后，模块会统计输出文件，调用 `binary_architecture_threader()` 将文件类型和二进制架构信息写入 P99 索引，并通过 `detect_root_dir_helper()` 查找 Linux 根文件系统。

```bash
# From modules/P16_yaffs1_extractor.sh (simplified)
yaffs1_extractor() {
  local lYAFFS_PATH_="${1:-}"
  local lEXTRACTION_DIR_="${2:-}"
  local lFILES_YAFFS_ARR=()

  [[ -f "${lYAFFS_PATH_}" ]] || return
  mkdir -p "${lEXTRACTION_DIR_}"

  python3 "${EXT_DIR}/android-rom-extract/extract_yaffs1.py" \
    "${lYAFFS_PATH_}" "${lEXTRACTION_DIR_}"

  mapfile -t lFILES_YAFFS_ARR < <(
    find "${lEXTRACTION_DIR_}" -type f ! -name "*.raw"
  )

  for lBINARY in "${lFILES_YAFFS_ARR[@]}"; do
    binary_architecture_threader \
      "${lBINARY}" "P16_yaffs1_extractor" &
  done
  wait_for_pid

  detect_root_dir_helper "${lEXTRACTION_DIR_}"
}
```

简而言之，该模块负责把 YAFFS v1 文件系统镜像还原为普通目录，并为后续静态分析准备文件索引和根目录信息。
