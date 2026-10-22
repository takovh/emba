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
# Description:  Installs Blint in the shared EMBA Python environment for APK SBOM generation

I18_blint() {
  module_title "${FUNCNAME[0]}"

  if [[ "${LIST_DEP}" -ne 1 && "${IN_DOCKER}" -ne 1 && "${DOCKER_SETUP}" -ne 0 && "${FULL}" -ne 1 ]]; then
    return 0
  fi

  print_pip_info "blint"

  # Host Docker installations use the tools in the image; listing must not install them.
  if [[ "${LIST_DEP}" -eq 1 || "${DOCKER_SETUP}" -eq 1 ]]; then
    return 0
  fi

  # installer.sh activates external/emba_venv before calling the tool installers.
  pip_install "blint"
  blint --help > /dev/null
  blint sbom --help > /dev/null
  echo "[+] Blint installed in the shared EMBA Python environment"
}
