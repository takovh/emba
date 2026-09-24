
## `P07_windows_exe_extract`

如果固件包含 Windows 或文件（某些物联网设备中常见），EMBA 会用于解压。`.exe``.msi``7z`

```bash
# From modules/P07_windows_exe_extract.sh (simplified)
exe_extractor() {
  local lFIRMWARE_PATH="${1:-}"
  local lEXTRACTION_DIR="${2:-}"

  mkdir "${lEXTRACTION_DIR}"
  print_output "[*] Extracting with 7z to ${lEXTRACTION_DIR}"
  # Extracts the contents of the Windows executable/installer
  7z x -o"${lEXTRACTION_DIR}" "${lFIRMWARE_PATH}"
}
```

这个命令类似于解压普通的压缩包，但它专门针对Windows可执行格式。