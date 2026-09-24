

## `*P60_deep_extractor`

这是“最后手段”，会对 **目前找到的每个** 文件 **进行多次** 提取。它确保即使是深度嵌套或异常堆积的部件也能被揭露。

EMBA并不止于一层。它通过反复扫描和解压固件中的文件来执行**深度提取**（`P60_deep_extractor.sh`）。如果在已解压的图层中发现新的归档或压缩文件，EMBA也会尝试解压。这就是它处理“套娃”效果的方式。

此外，固件通常包含常见的包格式，如Debian包（`.deb`）、Android包（`.apk`）、或OpenWrt包（`.ipk`）。该模块`P65_package_extractor.sh`专门识别并提取这些文件，并将其内容添加到整体解压文件系统中。

例如，以下是`P65_package_extractor.sh`如何处理Debian包的简化说明：

```bash
# Simplified from modules/P65_package_extractor.sh
deb_extractor() {
  local lDEB_ARCHIVES_ARR=() # List of .deb files found

  print_output "[*] Identifying Debian archives..."
  # Finds all .deb files in the extracted firmware
  mapfile -t lDEB_ARCHIVES_ARR < <(find "${FIRMWARE_PATH_CP}" -name "*.deb")

  if [[ "${#lDEB_ARCHIVES_ARR[@]}" -gt 0 ]]; then
    print_output "[*] Found ${#lDEB_ARCHIVES_ARR[@]} Debian archives - extracting them..."
    for lDEB in "${lDEB_ARCHIVES_ARR[@]}"; do
      local lR_PATH="${FIRMWARE_PATH_CP}" # Extract to the main firmware directory
      print_output "[*] Extracting $(basename "${lDEB}") to ${lR_PATH}"
      # Uses dpkg-deb to extract the package contents
      dpkg-deb --extract "${lDEB}" "${lR_PATH}" || true
    done
  fi
}
```
