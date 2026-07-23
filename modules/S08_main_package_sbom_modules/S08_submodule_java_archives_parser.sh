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

# Description:  Searches known locations for package management information
# shellcheck disable=SC2094

# 解析Java归档文件（JAR/WAR）以提取包信息
S08_submodule_java_archives_parser() {
  local lPACKAGING_SYSTEM="java_archive"
  local lOS_IDENTIFIED="${1:-}"

  sub_module_title "Java archive identification" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  local lJAVA_ARCHIVES_ARR=()
  local lJAVA_ARCHIVE=""
  local lJ_FILE=""
  local lAPP_LIC="NA"
  local lAPP_NAME="NA"
  local lAPP_VERS="NA"
  local lAPP_ARCH="NA"
  local lAPP_MAINT="NA"
  local lAPP_DESC="NA"
  local lAPP_VENDOR="NA"
  local lCPE_IDENTIFIER="NA"
  local lIMPLEMENT_TITLE="NA"
  export POS_RES=0
  local lMD5_CHECKSUM="NA"
  local lSHA256_CHECKSUM="NA"
  local lSHA512_CHECKSUM="NA"
  local lPURL_IDENTIFIER="NA"

  # if we have found multiple status files but all are the same -> we do not need to test duplicates
  local lPKG_CHECKED_ARR=()
  local lPKG_MD5=""
  local lJ_JAVA_FILE_NAME=""
  local lPOM_CHECKED_ARR=()

  # 从P99_CSV_LOG中提取所有Java归档文件路径（.jar和.war）
  mapfile -t lJAVA_ARCHIVES_ARR < <(grep "\.jar;\|\.war;" "${P99_CSV_LOG}" | cut -d ';' -f2 || true)

  if [[ "${#lJAVA_ARCHIVES_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lJAVA_ARCHIVES_ARR[@]}${NC} Java archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lJAVA_ARCHIVE in "${lJAVA_ARCHIVES_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lJAVA_ARCHIVE}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lJAVA_ARCHIVES_ARR[@]}${NC} Java archives:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

    for lJAVA_ARCHIVE in "${lJAVA_ARCHIVES_ARR[@]}" ; do
      # 验证文件类型是否为Java归档或ZIP文件
      lJ_FILE=$(file "${lJAVA_ARCHIVE}")
      if [[ ! "${lJ_FILE}" == *"Java archive data"* && ! "${lJ_FILE}" == *"Zip archive"* ]]; then
        continue
      fi
      lJ_JAVA_FILE_NAME=$(basename "${lJAVA_ARCHIVE}")

      # 通过MD5校验和去重，避免重复分析相同的归档文件
      lPKG_MD5="$(md5sum "${lJAVA_ARCHIVE}" | awk '{print $1}')"
      if [[ "${lPKG_CHECKED_ARR[*]}" == *"${lPKG_MD5}"* ]]; then
        print_output "[*] ${ORANGE}${lJAVA_ARCHIVE}${NC} already analyzed" "no_log"
        continue
      fi
      lPKG_CHECKED_ARR+=( "${lPKG_MD5}" )

      # 检查并解析MANIFEST.MF文件
      if unzip -l "${lJAVA_ARCHIVE}" -- *META-INF/MANIFEST.MF &>/dev/null; then
        local lJAVA_MANIFEST_FILE="${LOG_PATH_MODULE}/Java_${lJ_JAVA_FILE_NAME}_MANIFEST.MF"
        unzip -p "${lJAVA_ARCHIVE}" META-INF/MANIFEST.MF > "${lJAVA_MANIFEST_FILE}"
        if [[ -s "${lJAVA_MANIFEST_FILE}" ]]; then
          S08_java_manifest_handling "${lPACKAGING_SYSTEM}" "${lJAVA_ARCHIVE}" "${lJAVA_MANIFEST_FILE}"
        fi
      fi

      # 检查并解析pom.xml元数据文件
      if unzip -l "${lJAVA_ARCHIVE}" -- *pom.xml &>/dev/null ; then
        local lPOM_XML_ARR=()
        local lPOM_XML=""
        local lPOM_MD5=""
        # 提取所有pom.xml文件路径
        mapfile -t lPOM_XML_ARR < <(unzip -l "${lJAVA_ARCHIVE}" | awk '{print $4}' | grep pom.xml || true)
        if [[ "${#lPOM_XML_ARR[@]}" -gt 0 ]]; then
          write_log "[*] Found ${ORANGE}${#lPOM_XML_ARR[@]}${NC} Java pom.xml:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
          write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
          for lPOM_XML in "${lPOM_XML_ARR[@]}" ; do
            write_log "$(indent "$(orange "$(print_path "${lPOM_XML}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
          done

          write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
          write_log "[*] Analyzing ${ORANGE}${#lPOM_XML_ARR[@]}${NC} Java pom.xml:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
          write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

          # 分析每个pom.xml以提取版本和名称信息
          for lPOM_XML in "${lPOM_XML_ARR[@]}"; do
            local lJAVA_POM_XML_FILE="${LOG_PATH_MODULE}/Java_${lJ_JAVA_FILE_NAME}_POM_${RANDOM}.xml"
            unzip -p "${lJAVA_ARCHIVE}" "${lPOM_XML}" > "${lJAVA_POM_XML_FILE}"

            # 通过MD5校验和去重，避免重复分析相同的pom.xml文件
            lPOM_MD5="$(md5sum "${lJAVA_POM_XML_FILE}" | awk '{print $1}')"
            if [[ "${lPOM_CHECKED_ARR[*]}" == *"${lPOM_MD5}"* ]]; then
              print_output "[*] ${ORANGE}${lJAVA_POM_XML_FILE}${NC} already analyzed" "no_log"
              continue
            fi
            lPOM_CHECKED_ARR+=( "${lPOM_MD5}" )

            if [[ -s "${lJAVA_POM_XML_FILE}" ]]; then
              S08_java_pom_xml_handling "${lPACKAGING_SYSTEM}" "${lJAVA_ARCHIVE}" "${lJAVA_POM_XML_FILE}"
            fi
          done
        fi
      fi
    done

    if [[ "${POS_RES}" -eq 0 ]]; then
      write_log "[-] No JAVA packages found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  else
    write_log "[-] No JAVA package files found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  fi

  # 直接处理已存在的pom.xml文件（类似源代码仓库中的结构）
  # 从P99_CSV_LOG中提取所有pom.xml文件路径
  mapfile -t lJAVA_POM_XML_ARR < <(grep "pom\.xml;" "${P99_CSV_LOG}" | cut -d ';' -f2 || true)

  if [[ "${#lJAVA_POM_XML_ARR[@]}" -gt 0 ]] ; then
    write_log "[*] Found ${ORANGE}${#lJAVA_POM_XML_ARR[@]}${NC} Java pom.xml:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    for lJAVA_POM in "${lJAVA_POM_XML_ARR[@]}" ; do
      write_log "$(indent "$(orange "$(print_path "${lJAVA_POM}")")")" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    done

    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "[*] Analyzing ${ORANGE}${#lJAVA_POM_XML_ARR[@]}${NC} Java pom.xml:" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    write_log "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

    # 处理每个独立的pom.xml文件
    for lJAVA_POM_XML in "${lJAVA_POM_XML_ARR[@]}" ; do
      S08_java_pom_xml_handling "${lPACKAGING_SYSTEM}" "${lJAVA_POM_XML}" "${lJAVA_POM_XML}"
    done
    if [[ "${POS_RES}" -eq 0 ]]; then
      write_log "[-] No JAVA pom.xml found!" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    fi
  fi

  write_log "[*] ${lPACKAGING_SYSTEM} sub-module finished" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"

  if [[ "${POS_RES}" -eq 1 ]]; then
    print_output "[+] Java package SBOM results" "" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  else
    print_output "[*] No Java package SBOM results available"
  fi
}

# 解析Java MANIFEST.MF文件以提取包信息
S08_java_manifest_handling() {
  local lPACKAGING_SYSTEM="${1:-}"
  local lJAVA_ARCHIVE="${2:-}"
  local lJAVA_MANIFEST_FILE="${3:-}"

  local lAPP_NAME=""
  local lAPP_LIC=""
  local lAPP_VENDOR_CLEAR=""
  local lAPP_VENDOR=""
  local lAPP_VENDOR_ID=""
  local lBUNDLE_NAME=""
  local lIMPLEMENT_TITLE=""
  local lAPP_VERS=""
  local lAPP_VERS_ALT=""

  # MANIFEST文件中的命名规则比较混乱，可能需要字典来解析名称并生成可用于CVE查询的格式
  # 提取Application-Name字段
  lAPP_NAME=$(grep "Application-Name" "${lJAVA_MANIFEST_FILE}" | head -1 || true)
  lAPP_NAME=${lAPP_NAME/*:\ /}

  # 提取License字段
  lAPP_LIC=$(grep "License" "${lJAVA_MANIFEST_FILE}" | head -1 || true)
  lAPP_LIC=${lAPP_LIC/*:\ /}
  lAPP_LIC=$(clean_package_details "${lAPP_LIC}")

  # 提取Vendor字段
  lAPP_VENDOR_CLEAR=$(grep "Vendor: " "${lJAVA_MANIFEST_FILE}" | sort -u | head -1 || true)
  lAPP_VENDOR_CLEAR=${lAPP_VENDOR_CLEAR#*:\ }
  lAPP_VENDOR_CLEAR=${lAPP_VENDOR_CLEAR//[![:print:]]/}
  lAPP_VENDOR=$(clean_package_details "${lAPP_VENDOR_CLEAR}")
  # 需要一些翻译，例如：The Apache Software Foundation -> apache

  # 检查已弃用的Implementation-Vendor-Id字段
  lAPP_VENDOR_ID=$(grep "Implementation-Vendor-Id: " "${lJAVA_MANIFEST_FILE}" | sort -u | head -1 || true)
  lAPP_VENDOR_ID=${lAPP_VENDOR_ID#*:\ }
  # 将org.apache.shiro格式转换为apache:shiro:version格式
  lAPP_VENDOR_ID=${lAPP_VENDOR_ID#org\.}
  lAPP_VENDOR_ID=${lAPP_VENDOR_ID#com\.}
  lAPP_VENDOR_ID=${lAPP_VENDOR_ID//\./:}
  lAPP_VENDOR_ID=$(clean_package_details "${lAPP_VENDOR_ID}")

  # 提取替代包名称（Implementation-Title和Bundle-Name）
  lIMPLEMENT_TITLE=$(grep "Implementation-Title" "${lJAVA_MANIFEST_FILE}" | head -1 || true)
  lIMPLEMENT_TITLE=${lIMPLEMENT_TITLE#*:\ }
  lIMPLEMENT_TITLE=${lIMPLEMENT_TITLE//\ }
  lIMPLEMENT_TITLE=${lIMPLEMENT_TITLE//::/_}
  lIMPLEMENT_TITLE=$(clean_package_details "${lIMPLEMENT_TITLE}")
  lBUNDLE_NAME=$(grep "Bundle-Name:" "${lJAVA_MANIFEST_FILE}" | head -1 || true)
  lBUNDLE_NAME=${lBUNDLE_NAME#*:\ }
  lBUNDLE_NAME=${lBUNDLE_NAME//::/_}
  lBUNDLE_NAME=$(clean_package_details "${lBUNDLE_NAME}")

  # 提取版本信息
  lAPP_VERS=$(grep "Implementation-Version" "${lJAVA_MANIFEST_FILE}" | head -1 || true)
  lAPP_VERS=${lAPP_VERS#*:\ }
  lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
  lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")
  lAPP_VERS_ALT=$(grep "Bundle-Version" "${lJAVA_MANIFEST_FILE}" | head -1 || true)
  lAPP_VERS_ALT=${lAPP_VERS_ALT#*:\ }
  lAPP_VERS_ALT=$(clean_package_details "${lAPP_VERS_ALT}")
  lAPP_VERS_ALT=$(clean_package_versions "${lAPP_VERS_ALT}")

  # 如果APP_NAME未设置，使用IMPLEMENT_TITLE作为备选
  if [[ -z "${lAPP_NAME}" && -n "${lIMPLEMENT_TITLE}" ]]; then
    lAPP_NAME="${lIMPLEMENT_TITLE}"
  fi
  # 如果APP_NAME仍未设置，使用BUNDLE_NAME作为备选
  if [[ -z "${lAPP_NAME}" && -n "${lBUNDLE_NAME}" ]]; then
    lAPP_NAME="${lBUNDLE_NAME}"
  fi
  # 如果APP_VERS未设置，使用APP_VERS_ALT作为备选
  if [[ -z "${lAPP_VERS}" && -n "${lAPP_VERS_ALT}" ]]; then
    lAPP_VERS="${lAPP_VERS_ALT}"
  fi

  # 如果仍然没有找到名称，使用归档文件的基本名称（去掉.jar后缀）
  if [[ -z "${lAPP_NAME}" ]]; then
    lAPP_NAME="$(basename -s .jar "${lJAVA_ARCHIVE}")"
  fi
  lAPP_NAME=$(clean_package_details "${lAPP_NAME}")
  [[ -z "${lAPP_NAME}" ]] && return

  # 如果有vendor_id但没有app_vendor，使用已弃用的vendor_id
  if [[ -z "${lAPP_VENDOR}" && -n "${lAPP_VENDOR_ID}" ]]; then
    lAPP_VENDOR="${lAPP_VENDOR_ID}"
  fi
  # 如果关键信息都为空，则跳过处理
  if [[ -z "${lAPP_NAME}" && -z "${lAPP_LIC}" && -z "${lIMPLEMENT_TITLE}" && -z "${lAPP_VERS}" && -z "${lBUNDLE_NAME}" ]]; then
    return
  fi
  lAPP_VERS="${lAPP_VERS/\.release}"
  write_log "[*] Java MANIFEST details: ${ORANGE}${lJAVA_ARCHIVE}${NC} - name ${ORANGE}${lAPP_NAME:-NA}${NC} - version ${ORANGE}${lAPP_VERS:-NA}${NC}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
  # 生成SBOM条目
  S08_java_generate_sbom_entry "${lJAVA_ARCHIVE}" "${lPACKAGING_SYSTEM}-manifest" "${lAPP_VENDOR}" "${lAPP_NAME}" "${lAPP_VERS}" "${lAPP_DESC:-NA}" "${lAPP_LIC}"
  POS_RES=1
}

# 解析pom.xml文件以提取Java包信息
S08_java_pom_xml_handling() {
  local lPACKAGING_SYSTEM="${1:-}"
  local lJAVA_ARCHIVE="${2:-}"
  local lJAVA_POM_XML="${3:-}"

  local lPOM_XML_ARR=()
  local lPOM_XML=""
  local lAPP_VERS_POM_XML=""
  local lAPP_NAME_POM_XML=""
  local lAPP_NAME_CLEAR_POM_XML=""
  local lAPP_NAME_DESC_POM_XML=""
  local lAPP_NAME_LIC_POM_XML=""
  local lAPP_VERS=""
  local lAPP_NAME=""
  local lAPP_VENDOR=""
  local lAPP_NAME_PROPERTIES_VERSION=""
  local lAPP_NAME_PROPERTIES_NAME=""

  # 从pom.xml中提取主要版本信息（project->version）
  lAPP_VERS_POM_XML=$(xpath -e project/version//text\(\) "${lJAVA_POM_XML}" 2>/dev/null)
  # 提取artifactId作为包名
  lAPP_NAME_POM_XML=$(xpath -e project/artifactId//text\(\) "${lJAVA_POM_XML}" 2>/dev/null)
  # 提取项目名称
  lAPP_NAME_CLEAR_POM_XML=$(xpath -e project/name//text\(\) "${lJAVA_POM_XML}" 2>/dev/null)
  # 提取项目描述
  lAPP_NAME_DESC_POM_XML=$(xpath -e project/description//text\(\) "${lJAVA_POM_XML}" 2>/dev/null | tr '\n' ' ')
  # 提取许可证信息
  lAPP_NAME_LIC_POM_XML=$(xpath -e project/licenses/license/name//text\(\) "${lJAVA_POM_XML}" 2>/dev/null)
  if [[ -n "${lAPP_VERS_POM_XML}" ]]; then
    # 对于依赖项，可以检查pom.xml文件
    # 可以使用类似以下命令提取依赖信息：
      # unzip -p "${lJAVA_ARCHIVE}" "${lPOM_XML}" | xpath -e project/dependencies
      # unzip -p "${lJAVA_ARCHIVE}" "${lPOM_XML}" | xpath -e project/dependencies/dependency
      # unzip -p "${lJAVA_ARCHIVE}" "${lPOM_XML}" | xpath -e project/dependencies/dependency[1]/version
    lAPP_VERS="${lAPP_VERS_POM_XML}"
    lAPP_VERS=$(clean_package_details "${lAPP_VERS}")
    lAPP_VERS=$(clean_package_versions "${lAPP_VERS}")
    lAPP_NAME="${lAPP_NAME_POM_XML}"

    write_log "[*] Java pom.xml details: ${ORANGE}${lJAVA_ARCHIVE}${NC} - ${lJAVA_POM_XML} - version ${lAPP_VERS} / name ${lAPP_NAME} / ${lAPP_NAME_CLEAR_POM_XML:-NA} / ${lAPP_NAME_DESC_POM_XML:-NA} / license ${lAPP_NAME_LIC_POM_XML:-NA}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    # 生成SBOM条目
    S08_java_generate_sbom_entry "${lJAVA_ARCHIVE}" "${lPACKAGING_SYSTEM}-pom_xml" "${lAPP_VENDOR:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lAPP_NAME_DESC_POM_XML:-NA}" "${lAPP_NAME_LIC_POM_XML}"
    POS_RES=1
  fi

  # 检查properties中的版本信息
  local lAPP_NAME_PROPERTIES_VERS_POM_XML=()
  mapfile -t lAPP_NAME_PROPERTIES_VERS_POM_XML < <(xpath -e "project/properties/*[contains(name(),'.version')]" "${lJAVA_POM_XML}" 2>/dev/null)
  for lAPP_NAME_PROPERTIES_VERSION in "${lAPP_NAME_PROPERTIES_VERS_POM_XML[@]}"; do
    # 例如：<spotbugs.version>4.8.6.0</spotbugs.version>
    lAPP_NAME_PROPERTIES_NAME=${lAPP_NAME_PROPERTIES_VERSION/\.version*}
    # 例如：<spotbugs
    lAPP_NAME_PROPERTIES_NAME=${lAPP_NAME_PROPERTIES_NAME//<}
    lAPP_NAME_PROPERTIES_VERSION=${lAPP_NAME_PROPERTIES_VERSION/<\/*\.version>/}
    lAPP_NAME_PROPERTIES_VERSION=${lAPP_NAME_PROPERTIES_VERSION/*\.version>}
    lAPP_VERS=$(clean_package_versions "${lAPP_NAME_PROPERTIES_VERSION}")
    lAPP_NAME="${lAPP_NAME_PROPERTIES_NAME}"
    local lAPP_LIC="NA"
    local lAPP_DESC="NA"

    write_log "[*] Java pom.xml details: ${ORANGE}${lJAVA_ARCHIVE}${NC} - ${lJAVA_POM_XML} - version ${lAPP_VERS} / name ${lAPP_NAME}" "${LOG_PATH_MODULE}/${lPACKAGING_SYSTEM}.txt"
    # 生成SBOM条目
    S08_java_generate_sbom_entry "${lJAVA_ARCHIVE}" "${lPACKAGING_SYSTEM}-pom_xml" "${lAPP_VENDOR:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lAPP_DESC}" "${lAPP_LIC}"
    POS_RES=1
  done
}

# 生成Java包的SBOM条目
S08_java_generate_sbom_entry() {
  local lJAVA_ARCHIVE="${1:-}"
  local lPACKAGING_SYSTEM="${2:-}"
  local lAPP_VENDOR="${3:-}"
  local lAPP_NAME="${4:-}"
  local lAPP_VERS="${5:-}"
  local lAPP_DESC="${6:-}"
  local lAPP_LIC="${7:-}"

  local lOS_IDENTIFIED="generic"
  local lAPP_MAINT=""
  local lAPP_ARCH=""

  # 计算文件的哈希值
  if [[ -f "${lJAVA_ARCHIVE}" ]]; then
    lMD5_CHECKSUM="$(md5sum "${lJAVA_ARCHIVE}" | awk '{print $1}')"
    lSHA256_CHECKSUM="$(sha256sum "${lJAVA_ARCHIVE}" | awk '{print $1}')"
    lSHA512_CHECKSUM="$(sha512sum "${lJAVA_ARCHIVE}" | awk '{print $1}')"
  fi

  # 构建CPE标识符
  lCPE_IDENTIFIER="cpe:${CPE_VERSION}:a:${lAPP_VENDOR}:${lAPP_NAME}:${lAPP_VERS}:*:*:*:*:*:*"

  # 构建PURL标识符
  lPURL_IDENTIFIER=$(build_purl_identifier "${lOS_IDENTIFIED:-NA}" "java" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_ARCH:-NA}")
  local lSTRIPPED_VERSION="::${lAPP_NAME}:${lAPP_VERS:-NA}"

  # 添加Java归档路径信息到属性数组
  # 待办事项：未来应检查包、包哈希以及包中包含的文件
  local lPROP_ARRAY_INIT_ARR=()
  if [[ -f "${lJAVA_ARCHIVE}" ]]; then
    lPROP_ARRAY_INIT_ARR+=( "source_path:${lJAVA_ARCHIVE}" )
  fi
  lPROP_ARRAY_INIT_ARR+=( "minimal_identifier:${lSTRIPPED_VERSION}" )
  lPROP_ARRAY_INIT_ARR+=( "vendor_name:${lAPP_VENDOR}" )
  lPROP_ARRAY_INIT_ARR+=( "product_name:${lAPP_NAME}" )
  lPROP_ARRAY_INIT_ARR+=( "confidence:high" )

  # 构建SBOM属性数组
  build_sbom_json_properties_arr "${lPROP_ARRAY_INIT_ARR[@]}"

  # 构建哈希数组，如果已存在相同结果则跳过
  if ! build_sbom_json_hashes_arr "${lJAVA_ARCHIVE}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lPACKAGING_SYSTEM}"; then
    write_log "[*] Already found results for ${lAPP_NAME} / ${lAPP_VERS} / ${lPACKAGING_SYSTEM}" "${S08_DUPLICATES_LOG}"
    return
  fi

  # 创建SBOM组件条目
  build_sbom_json_component_arr "${lPACKAGING_SYSTEM}" "${lAPP_TYPE:-library}" "${lAPP_NAME:-NA}" "${lAPP_VERS:-NA}" "${lAPP_VENDOR:-NA}" "${lAPP_LIC:-NA}" "${lCPE_IDENTIFIER:-NA}" "${lPURL_IDENTIFIER:-NA}" "${lAPP_DESC:-NA}"

  # 写入CSV日志
  write_csv_log "${lPACKAGING_SYSTEM}" "${lJAVA_ARCHIVE}" "${lMD5_CHECKSUM:-NA}/${lSHA256_CHECKSUM:-NA}/${lSHA512_CHECKSUM:-NA}" "${lAPP_NAME}" "${lAPP_VERS}" "${lSTRIPPED_VERSION:-NA}" "${lAPP_LIC}" "${lAPP_MAINT}" "${lAPP_ARCH}" "${lCPE_IDENTIFIER}" "${lPURL_IDENTIFIER}" "${SBOM_COMP_BOM_REF:-NA}" "${lAPP_DESC}"
}


