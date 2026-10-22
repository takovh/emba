#!/bin/bash -p

# EMBA - EMBEDDED LINUX ANALYZER
#
# EMBA comes with ABSOLUTELY NO WARRANTY. This is free software, and you are
# welcome to redistribute it under the terms of the GNU General Public License.
# See LICENSE file for usage of this software.
#
# EMBA is licensed under GPLv3
# SPDX-License-Identifier: GPL-3.0-only
#
# Description:  Identifies Android APK components using Blint

S08_submodule_android_apk_sbom() {
  local lWORK_DIR="${LOG_PATH_MODULE}/android_apk_blint"
  local lAPK=""
  local lHASH=""
  local lRUN_DIR=""
  local lSTATUS=""
  local lEXIT=0
  local lIMPORT_PID=""
  local lDEPENDENCY=""
  local lAPK_FILES_ARR=()
  local lCOMMAND_ARR=()
  local -A lSEEN_APKS=()

  sub_module_title "Android APK SBOM identification (Blint)" "${LOG_PATH_MODULE}/android_apk.txt"
  mkdir -p "${lWORK_DIR}" "${SBOM_LOG_PATH}"
  : > "${lWORK_DIR}/status.ndjson"

  for lDEPENDENCY in blint jq jo timeout unzip sha256sum realpath; do
    if ! command -v "${lDEPENDENCY}" > /dev/null; then
      print_output "[-] Missing ${lDEPENDENCY} - Android APK analysis skipped"
      return 0
    fi
  done
  if [[ ! -f "${CONFIG_DIR}/android_apk_sbom.jq" ]]; then
    print_output "[-] Missing android_apk_sbom.jq - Android APK analysis skipped"
    return 0
  fi

  if [[ -f "${P99_CSV_LOG}" ]]; then
    mapfile -t lAPK_FILES_ARR < <(awk -F ';' 'tolower($2) ~ /\.apk$/ {print $2}' "${P99_CSV_LOG}" | sort -u)
  fi
  # A standalone APK can be outside the extracted-file index.
  if [[ "${FIRMWARE_PATH_BAK,,}" == *.apk && -f "${FIRMWARE_PATH_BAK}" ]]; then
    lAPK_FILES_ARR+=( "${FIRMWARE_PATH_BAK}" )
  fi

  for lAPK in "${lAPK_FILES_ARR[@]}"; do
    [[ -f "${lAPK}" ]] || continue
    if ! is_android_apk "${lAPK}"; then
      jq -cn --arg path "${lAPK}" '{path: $path, status: "not_android_apk"}' >> "${lWORK_DIR}/status.ndjson"
      continue
    fi
    lHASH=$(sha256sum -- "${lAPK}")
    lHASH="${lHASH%% *}"
    if [[ -n "${lSEEN_APKS[${lHASH}]:-}" ]]; then
      if [[ -f "${lSEEN_APKS[${lHASH}]}/component_files.txt" ]]; then
        android_apk_add_source "${lSEEN_APKS[${lHASH}]}" "${lAPK}"
      fi
      jq -cn --arg path "${lAPK}" --arg run "${lSEEN_APKS[${lHASH}]}" \
        '{path: $path, status: "duplicate", report_directory: $run}' >> "${lWORK_DIR}/status.ndjson"
      continue
    fi
    # A new directory prevents stale reports from making a failed rerun look successful.
    lRUN_DIR=$(mktemp -d "${lWORK_DIR}/${lHASH}.XXXXXX")
    lRUN_DIR=$(realpath -- "${lRUN_DIR}")
    lSEEN_APKS["${lHASH}"]="${lRUN_DIR}"
    lCOMMAND_ARR=(blint --no-banner sbom -i "$(realpath -- "${lAPK}")" -o "${lRUN_DIR}/blint.cdx.json")
    lEXIT=0
    # Keep optional sidecars away from the read-only /emba checkout in Docker.
    (cd "${lRUN_DIR}" && timeout --kill-after=10s 600s "${lCOMMAND_ARR[@]}") \
      > "${lRUN_DIR}/blint.log" 2>&1 || lEXIT=$?
    lSTATUS="failed"
    if [[ "${lEXIT}" -eq 124 || "${lEXIT}" -eq 137 ]]; then
      lSTATUS="timeout"
    elif [[ "${lEXIT}" -eq 0 && -s "${lRUN_DIR}/blint.cdx.json" ]]; then
      # A background subshell keeps errexit active even when wait handles its failure.
      lEXIT=0
      (set -e; android_apk_import_sbom "${lRUN_DIR}" "${lAPK}" "${lHASH}") > "${lRUN_DIR}/import.log" 2>&1 &
      lIMPORT_PID="$!"
      wait "${lIMPORT_PID}" || lEXIT=$?
      if [[ "${lEXIT}" -eq 0 ]]; then
        lSTATUS="success"
        if [[ -s "${lRUN_DIR}/unresolved_dependencies.txt" ]]; then
          lSTATUS="partial"
        fi
      fi
    fi
    if [[ "${lSTATUS}" != "success" ]]; then
      print_output "[-] Android APK ${lSTATUS}: ${lAPK} (exit ${lEXIT}, details: ${lRUN_DIR})"
    fi
    jq -cn --arg path "${lAPK}" --arg status "${lSTATUS}" --arg run "${lRUN_DIR}" --argjson exit_code "${lEXIT}" \
      '{path: $path, status: $status, exit_code: $exit_code, report_directory: $run}' >> "${lWORK_DIR}/status.ndjson"
  done
  jq -s 'group_by(.status) | map({key: .[0].status, value: length}) | from_entries' \
    "${lWORK_DIR}/status.ndjson" > "${lWORK_DIR}/summary.json"
  print_output "[*] Android APK analysis summary: $(jq -c . "${lWORK_DIR}/summary.json")" "" "${lWORK_DIR}/summary.json"
}

is_android_apk() {
  local lAPK="${1:-}"
  local lMAGIC=""
  local lCONTENTS=""
  lMAGIC=$(od -An -tx1 -N4 -- "${lAPK}" | tr -d ' \n')
  [[ "${lMAGIC}" == "504b0304" ]] || return 1
  lCONTENTS=$(unzip -Z1 "${lAPK}" 2>/dev/null) || return 1
  # Do not use grep -q in a pipe: SIGPIPE otherwise rejects large valid archives.
  grep -Fx 'AndroidManifest.xml' <<< "${lCONTENTS}" > /dev/null
}

android_apk_add_source() {
  local lRUN_DIR="${1:-}"
  local lAPK="${2:-}"
  local lFILE=""
  while IFS= read -r lFILE; do
    [[ -f "${lFILE}" ]] || continue
    jq --arg path "${lAPK}" '.properties += [{name: "EMBA:sbom:source_location:additional_source_path", value: $path}] |
      .properties |= unique_by([.name, .value])' "${lFILE}" > "${lFILE}.tmp"
    mv -- "${lFILE}.tmp" "${lFILE}"
  done < "${lRUN_DIR}/component_files.txt"
}

android_apk_import_sbom() {
  local lRUN_DIR="${1:-}"
  local lAPK="${2:-}"
  local lAPK_HASH="${3:-}"
  local lRECORD=""
  local lCOMP=""
  local lKEY=""
  local lFILE=""
  local lBUILT_FILE=""
  local lORIGINAL_REF=""
  local lFINAL_REF=""
  local lNAME=""
  local lVERSION=""
  local lPURL=""
  local lROOT=""
  local lDEP=""
  local lDEP_REF=""
  local lDEPENDS=""
  local lTOOL=""
  local lTOOL_KEY=""
  local -A lREF_MAP=()

  jq -f "${CONFIG_DIR}/android_apk_sbom.jq" "${lRUN_DIR}/blint.cdx.json" > "${lRUN_DIR}/normalized.json" || return 1
  mkdir -p "${SBOM_LOG_PATH}/SBOM_deps" "${SBOM_LOG_PATH}/SBOM_tools" "${lRUN_DIR}/components"
  : > "${lRUN_DIR}/component_files.txt"
  : > "${lRUN_DIR}/reference_map.ndjson"
  : > "${lRUN_DIR}/unresolved_dependencies.txt"

  while IFS= read -r lRECORD; do
    lCOMP=$(jq -c '.component' <<< "${lRECORD}")
    lROOT=$(jq -r '.root' <<< "${lRECORD}")
    lORIGINAL_REF=$(jq -r '.original_ref' <<< "${lRECORD}")
    lNAME=$(jq -r '.name' <<< "${lCOMP}")
    lVERSION=$(jq -r '.version' <<< "${lCOMP}")
    lPURL=$(jq -r '.purl // ""' <<< "${lCOMP}")
    # Unknown versions stay APK-local; hashes and qualifiers prevent ABI collisions.
    lKEY=$(jq -cS --arg apk "${lAPK_HASH}" --arg root "${lROOT}" --arg ref "${lORIGINAL_REF}" '
      if $root == "true" then {apk: $apk, root: .purl, name: .name}
      elif (.purl // "") != "" and .version != "" and .version != "latest" then
        {purl, version, hashes: (.hashes | sort_by(.alg)), abi: [.properties[] | select(.name | test("abi|arch"; "i"))]}
      else {apk: $apk, ref: $ref, purl, name, hashes} end' <<< "${lCOMP}" | sha256sum)
    lKEY="${lKEY%% *}"
    lFINAL_REF="android-apk-${lKEY}"
    lFILE="${SBOM_LOG_PATH}/android_apk_${lKEY}.json"
    if [[ "${lROOT}" == "true" ]]; then
      # NA disables name/version merging in the shared hash helper.
      build_sbom_json_hashes_arr "${lAPK}" "NA" "NA" "android_apk"
    else
      export HASHES_ARR=()
      mapfile -t HASHES_ARR < <(jq -c '.hashes[]' <<< "${lCOMP}")
    fi
    build_sbom_json_properties_arr "source_path:${lAPK}" "confidence:$(jq -r '
      .properties[] | select(.name == "gst:confidence").value | tonumber |
      if . >= 0.8 then "high" elif . >= 0.5 then "medium" elif . >= 0.2 then "low" else "very-low" end' <<< "${lCOMP}")"
    # A digest is used as the temporary name so archive-controlled names cannot form paths.
    SBOM_LOG_PATH="${lRUN_DIR}/components" build_sbom_json_component_arr "android_apk" "$(jq -r '.type' <<< "${lCOMP}")" "${lKEY}" \
      "${lVERSION}" "$(jq -r '.supplier.name // ""' <<< "${lCOMP}")" "NA" \
      "$(jq -r '.cpe // "NA"' <<< "${lCOMP}")" "${lPURL}" "NA"
    lBUILT_FILE="${lRUN_DIR}/components/android_apk_${lKEY}_${SBOM_COMP_BOM_REF}.json"
    jq --argjson component "${lCOMP}" --arg ref "${lFINAL_REF}" '
      . + ($component | del(.hashes, .properties)) | .["bom-ref"] = $ref |
      .properties += ($component.properties + [{name: "gst:blint:deep", value: "0"}]) |
      if .group == "" then .group = "android_apk" else . end' "${lBUILT_FILE}" > "${lFILE}.tmp"
    if [[ -f "${lFILE}" ]]; then
      jq -s '.[0] as $old | .[1] | .properties = (($old.properties + .properties) | unique_by([.name, .value])) |
        .hashes = ((($old.hashes // []) + (.hashes // [])) | unique_by([.alg, .content]))' \
        "${lFILE}" "${lFILE}.tmp" > "${lFILE}.merged"
      mv -- "${lFILE}.merged" "${lFILE}.tmp"
    fi
    mv -- "${lFILE}.tmp" "${lFILE}"
    rm -- "${lBUILT_FILE}"
    printf '%s\n' "${lFILE}" >> "${lRUN_DIR}/component_files.txt"
    if [[ -n "${lORIGINAL_REF}" ]]; then
      lREF_MAP["${lORIGINAL_REF}"]="${lFINAL_REF}"
      jq -cn --arg old "${lORIGINAL_REF}" --arg new "${lFINAL_REF}" '{old: $old, new: $new}' >> "${lRUN_DIR}/reference_map.ndjson"
    fi
    write_csv_log "android_apk" "${lAPK}" "NA" "${lNAME}" "${lVERSION}" "NA" "NA" "NA" "NA" "NA" "${lPURL}" "${lFINAL_REF}" "Blint APK component"
  done < <(jq -c '.components[]' "${lRUN_DIR}/normalized.json")

  # Resolve against imported components only; never publish dangling Blint references.
  while IFS= read -r lDEP; do
    lORIGINAL_REF=$(jq -r '.ref // ""' <<< "${lDEP}")
    lFINAL_REF="${lREF_MAP[${lORIGINAL_REF:-missing}]:-}"
    [[ -n "${lFINAL_REF}" ]] || continue
    lDEPENDS="[]"
    while IFS= read -r lDEP_REF; do
      if [[ -n "${lREF_MAP[${lDEP_REF:-missing}]:-}" ]]; then
        lDEPENDS=$(jq -c --arg ref "${lREF_MAP[${lDEP_REF}]}" '. + [$ref] | unique' <<< "${lDEPENDS}")
      else
        printf '%s\n' "${lDEP_REF}" >> "${lRUN_DIR}/unresolved_dependencies.txt"
      fi
    done < <(jq -r '.dependsOn[]?' <<< "${lDEP}")
    lFILE="${SBOM_LOG_PATH}/SBOM_deps/SBOM_dependency_${lFINAL_REF}.json"
    jq -cn --arg ref "${lFINAL_REF}" --argjson deps "${lDEPENDS}" '{ref: $ref, dependsOn: $deps}' > "${lFILE}.tmp"
    if [[ -f "${lFILE}" ]]; then
      jq -s '.[0] as $old | .[1] | .dependsOn = (($old.dependsOn + .dependsOn) | unique)' \
        "${lFILE}" "${lFILE}.tmp" > "${lFILE}.merged"
      mv -- "${lFILE}.merged" "${lFILE}.tmp"
    fi
    mv -- "${lFILE}.tmp" "${lFILE}"
  done < <(jq -c '.dependencies[]' "${lRUN_DIR}/normalized.json")

  while IFS= read -r lTOOL; do
    lTOOL_KEY=$(printf '%s' "${lTOOL}" | sha256sum)
    lTOOL_KEY="${lTOOL_KEY%% *}"
    printf '%s\n' "${lTOOL}" > "${SBOM_LOG_PATH}/SBOM_tools/android_apk_${lTOOL_KEY}.json"
  done < <(jq -c '.tools[]' "${lRUN_DIR}/normalized.json")
}
