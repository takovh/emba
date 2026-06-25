#!/bin/bash
main() {
  local firmware_base_path="/home/gst/firmware_all"
  # local firmware="${firmware_base_path}/camera.zip"
  # local firmware="${firmware_base_path}/android_system.img"
  # local firmware="${firmware_base_path}/update_smdt.zip"
  # local firmware="${firmware_base_path}/miui_COROT_V14.0.14.0.TMLCNXM_0c4fddade3_13.0.zip"
  # local firmware="${firmware_base_path}/payload.bin"
  # local firmware="${firmware_base_path}/Xiaomi_Updater_v1012_A10.exe"
  # local firmware="${firmware_base_path}/smdt_3288A_userdebug_20250305_235357.img"
  local firmware="${firmware_base_path}/smdt_6323se_android_20260428_170559.zip"
  local emba_path="/home/gst/yzhang/emba"
  local output_dir="/home/gst/yzhang/emba-log/$(date +%Y%m%d%H%M%S)"
  echo "固件："${firmware}
  echo "输出目录："${output_dir}
  cd ${emba_path}
  # sudo ${emba_path}/emba -V
  # sudo ${emba_path}/emba -f ${firmware} -l ${output_dir} -m p -D
  sudo ${emba_path}/emba -f ${firmware} -l ${output_dir} -p ${emba_path}/scan-profiles/my-sbom.emba
}

main "$@"
