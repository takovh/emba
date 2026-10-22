
## `P14_ext_mounter`

如果EMBA检测到Linux或文件系统，该模块会“挂载”它（使其像普通文件夹一样可访问），并复制其内容。`ext2` `ext3` `ext4`

```bash
# From modules/P14_ext_mounter.sh (simplified)
ext_extractor() {
  local lEXT_PATH_="${1:-}"
  local lTMP_EXT_MOUNT="${TMP_DIR}/ext_mount_${RANDOM}"

  mkdir -p "${lTMP_EXT_MOUNT}"
  print_output "[*] Trying to mount ${lEXT_PATH_} to ${lTMP_EXT_MOUNT} directory"
  # Mounts the image read-only
  mount -o ro "${lEXT_PATH_}" "${lTMP_EXT_MOUNT}"
  # If successful, copy files to the extraction directory
  if mount | grep -q ext_mount; then
    cp -pri "${lTMP_EXT_MOUNT}"/* "${lEXTRACTION_DIR_}"
    umount "${lTMP_EXT_MOUNT}" # Unmount after copying
  fi
}
```

这段摘要展示了模块如何创建一个临时挂载点，将文件系统镜像挂载在那里，复制内容，然后通过卸载来清理。
