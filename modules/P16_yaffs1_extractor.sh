#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# Copyright 2020-2025 Siemens Energy AG
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Author(s): Michael Messner

# Description: Extracts YAFFS v1 filesystem images
# Pre-checker threading mode - if set to 1, these modules will run in threaded mode
export PRE_THREAD_ENA=0

P16_yaffs1_extractor() {
  local lNEG_LOG=0

  if [[ "${YAFFS1_DETECTED}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "YAFFS v1 filesystem extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    local lEXTRACTION_DIR="${LOG_DIR}"/firmware/yaffs1_extracted/

    yaffs1_extractor "${FIRMWARE_PATH}" "${lEXTRACTION_DIR}"

    if [[ -s "${P99_CSV_LOG}" ]] && grep -q "^${FUNCNAME[0]};" "${P99_CSV_LOG}" ; then
      export FIRMWARE_PATH="${LOG_DIR}"/firmware/
      backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
      lNEG_LOG=1
    fi
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
  fi
}

yaffs1_extractor() {
  local lYAFFS_PATH_="${1:-}"
  local lEXTRACTION_DIR_="${2:-}"

  local lFILES_YAFFS_ARR=()
  local lBINARY=""
  local lWAIT_PIDS_P99_ARR=()

  if ! [[ -f "${lYAFFS_PATH_}" ]]; then
    print_output "[-] No file for extraction provided"
    return
  fi

  sub_module_title "YAFFS v1 filesystem extractor"

  print_output "[*] Extracting YAFFS v1 filesystem from ${ORANGE}${lYAFFS_PATH_}${NC} to ${ORANGE}${lEXTRACTION_DIR_}${NC}"

  if [[ -d "${lYAFFS_PATH_}" ]]; then
    print_output "[*] lYAFFS_PATH_ is a DIRECTORY. Contents:"
    ls -la "${lYAFFS_PATH_}" | tee -a "${LOG_FILE}"
  elif [[ -f "${lYAFFS_PATH_}" ]]; then
    print_output "[*] lYAFFS_PATH_ is a regular file."
    print_output "[*] File type: $(file "${lYAFFS_PATH_}")"
  else
    print_output "[*] lYAFFS_PATH_ is NEITHER a file nor a directory."
  fi

  mkdir -p "${lEXTRACTION_DIR_}"
  local lYAFFS_CMD="${EXT_DIR}/android-rom-extract/extract_yaffs1.py"
  # print_output "[*] EXT_DIR contents: $(ls -la "${EXT_DIR}" 2>&1)"
  if [[ -f "${lYAFFS_CMD}" ]]; then
    print_output "[*] Running: ${ORANGE}python3 ${lYAFFS_CMD} ${lYAFFS_PATH_} ${lEXTRACTION_DIR_}${NC}"
    python3 "${lYAFFS_CMD}" "${lYAFFS_PATH_}" "${lEXTRACTION_DIR_}" 2>&1 | tee -a "${LOG_FILE}" || true
  else
    print_output "[-] ${lYAFFS_CMD} not found"
    return
  fi

  mapfile -t lFILES_YAFFS_ARR < <(find "${lEXTRACTION_DIR_}" -type f ! -name "*.raw")

  print_output "[*] Extracted ${ORANGE}${#lFILES_YAFFS_ARR[@]}${NC} files from the firmware image."
  print_output "[*] Populating backend data for ${ORANGE}${#lFILES_YAFFS_ARR[@]}${NC} files ... could take some time" "no_log"

  for lBINARY in "${lFILES_YAFFS_ARR[@]}" ; do
    print_output "[*] Processing binary_architecture_threader: ${lBINARY}" "no_log"
    binary_architecture_threader "${lBINARY}" "P16_yaffs1_extractor" &
    local lTMP_PID="$!"
    lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
  done
  wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"

  write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "further details"
  write_csv_log "YAFFS v1 filesystem extractor" "${lYAFFS_PATH_}" "${lEXTRACTION_DIR_}" "${#lFILES_YAFFS_ARR[@]}" "via extract_yaffs1.py"

  detect_root_dir_helper "${lEXTRACTION_DIR_}"
}
