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
# Author(s): EMBA team

# Description: Converts Android sparse images and extracts named super partitions.
# Pre-checker threading mode - image conversion must finish before subsequent extractors.
export PRE_THREAD_ENA=0

P26_android_sparse_super() {
  local lNEG_LOG=0

  if [[ "${ANDROID_SPARSE:-0}" -eq 1 || "${ANDROID_SUPER:-0}" -eq 1 ]]; then
    module_log_init "${FUNCNAME[0]}"
    module_title "Android sparse image and super partition extractor"
    pre_module_reporter "${FUNCNAME[0]}"

    local lEXTRACTION_DIR="${LOG_DIR}/firmware/android_image_extracted/"
    local lIMAGE_TYPE="super"
    if [[ "${ANDROID_SPARSE:-0}" -eq 1 ]]; then
      lIMAGE_TYPE="sparse"
    fi

    android_image_extractor "${FIRMWARE_PATH}" "${lEXTRACTION_DIR}" "${lIMAGE_TYPE}" || true

    if [[ -s "${P99_CSV_LOG}" ]] && grep -q "^${FUNCNAME[0]};" "${P99_CSV_LOG}"; then
      export FIRMWARE_PATH="${LOG_DIR}/firmware/"
      backup_var "FIRMWARE_PATH" "${FIRMWARE_PATH}"
      lNEG_LOG=1
    fi
    module_end_log "${FUNCNAME[0]}" "${lNEG_LOG}"
  fi
}

# Arguments: input image, extraction directory, image type (sparse or super).
android_image_extractor() {
  local lIMAGE="${1:-}"
  local lOUTPUT_DIR="${2:-}"
  local lIMAGE_TYPE="${3:-}"
  local lRAW_IMAGE="${lIMAGE}"
  local lBINARY=""
  local lFILES_ARR=()
  local lWAIT_PIDS_P99_ARR=()
  local lTOOLS_DIR="${EXT_DIR}/android-rom-extract"

  if [[ "${lIMAGE_TYPE}" != "sparse" && "${lIMAGE_TYPE}" != "super" ]]; then
    print_output "[-] Android image type must be sparse or super"
    return
  fi

  sub_module_title "Android sparse image and super partition extractor"

  mkdir -p "${lOUTPUT_DIR}" || return
  if [[ "${lIMAGE_TYPE}" == "sparse" ]]; then
    lRAW_IMAGE="${lOUTPUT_DIR}/image.img"
    print_output "[*] Converting Android sparse image ${ORANGE}${lIMAGE}${NC} to ${ORANGE}${lRAW_IMAGE}${NC}"
    if ! python3 "${lTOOLS_DIR}/simg2img.py" "${lIMAGE}" "${lRAW_IMAGE}" >> "${LOG_FILE}" 2>&1; then
      print_output "[-] Android sparse conversion failed; see module log"
      rm -f "${lRAW_IMAGE}"
      return
    fi
  fi

  if [[ "${lIMAGE_TYPE}" == "super" ]] || \
      [[ "$(od -An -tx1 -j4096 -N4 "${lRAW_IMAGE}" 2>/dev/null | tr -d ' \n' || true)" == "67446c61" ]] || \
      [[ "$(od -An -tx1 -j8192 -N4 "${lRAW_IMAGE}" 2>/dev/null | tr -d ' \n' || true)" == "67446c61" ]]; then
    if [[ "${lRAW_IMAGE}" != "${lIMAGE}" ]]; then
      # Intermediate containers are excluded from subsequent EMBA file indexing.
      mv "${lRAW_IMAGE}" "${lOUTPUT_DIR}/image.raw" || return
      lRAW_IMAGE="${lOUTPUT_DIR}/image.raw"
    fi
    if [[ ! -f "${lTOOLS_DIR}/lpunpack.py" ]]; then
      print_output "[-] Missing Android super extractor: ${lTOOLS_DIR}/lpunpack.py"
      return
    fi
    print_output "[*] Extracting named logical partitions from ${ORANGE}${lRAW_IMAGE}${NC}"
    # Pass a raw image so lpunpack never writes its unsparse image next to a read-only input.
    if ! python3 "${lTOOLS_DIR}/lpunpack.py" "${lRAW_IMAGE}" "${lOUTPUT_DIR}/partitions" >> "${LOG_FILE}" 2>&1; then
      print_output "[-] Android super partition extraction failed; see module log"
      return
    fi
  fi

  mapfile -d '' -t lFILES_ARR < <(find "${lOUTPUT_DIR}" -type f ! -name "*.raw" -size +0c -print0)

  if [[ "${#lFILES_ARR[@]}" -eq 0 ]]; then
    print_output "[-] Android image contains no non-empty logical partitions"
    return
  fi
  for lBINARY in "${lFILES_ARR[@]}"; do
    binary_architecture_threader "${lBINARY}" "P26_android_sparse_super" &
    local lTMP_PID="$!"
    lWAIT_PIDS_P99_ARR+=( "${lTMP_PID}" )
  done
  wait_for_pid "${lWAIT_PIDS_P99_ARR[@]}"
  print_output "[+] Prepared ${ORANGE}${#lFILES_ARR[@]}${NC} Android partition images for filesystem extraction"
  write_csv_log "Extractor module" "Original file" "extracted file/dir" "file counter" "further details"
  write_csv_log "Android sparse/super extractor" "${lIMAGE}" "${lOUTPUT_DIR}" "${#lFILES_ARR[@]}" "simg2img.py / lpunpack.py"
}
