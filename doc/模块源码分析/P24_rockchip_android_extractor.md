## `P24_rockchip_android_extractor`

如果 `P02_firmware_bin_file_check` 在固件头部识别到 `RKAF`、`RKFW` 或 `RKFP` 标志，EMBA 会调用该模块拆分 Rockchip Android 固件。

模块使用 `rkunpack.py` 解析 Rockchip 容器：`RKAF` 按文件表导出镜像，`RKFW` 导出 `BOOT` 和内嵌的 `embedded-update.img`，`RKFP` 按分区表导出各分区。结果写入 `${LOG_DIR}/firmware/rockchip_extracted/`，随后通过 `binary_architecture_threader()` 登记到 P99 文件索引，供后续提取和静态分析模块使用。

```bash
# From modules/P24_rockchip_android_extractor.sh (simplified)
rockchip_extractor() {
  local lFIRMWARE_PATH_="${1:-}"
  local lEXTRACTION_DIR_="${2:-}"
  local lFILES_ARR=()

  [[ -f "${lFIRMWARE_PATH_}" ]] || return

  python3 "${EXT_DIR}/android-rom-extract/rkunpack.py" \
    -o "${lEXTRACTION_DIR_}" "${lFIRMWARE_PATH_}"

  mapfile -t lFILES_ARR < <(
    find "${lEXTRACTION_DIR_}" -type f ! -name "*.raw"
  )

  for lBINARY in "${lFILES_ARR[@]}"; do
    binary_architecture_threader \
      "${lBINARY}" "P24_rockchip_android_extractor" &
  done
  wait_for_pid

  write_csv_log "Rockchip extractor" \
    "${lFIRMWARE_PATH_}" "${lEXTRACTION_DIR_}" \
    "${#lFILES_ARR[@]}" "via rkunpack.py"
}
```

简而言之，该模块将 Rockchip 固件容器拆分为可继续识别和分析的启动镜像、更新镜像或分区文件。
