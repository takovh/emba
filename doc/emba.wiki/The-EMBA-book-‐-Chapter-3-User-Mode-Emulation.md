# Chapter 3: User-Mode Emulation: Running Programs in Isolation

User-mode emulation, enabled with the `-E` flag, is different. Instead of booting a whole operating system, it focuses on running **individual executable programs** from the firmware using `qemu-user-static`. This is faster and uses fewer resources, making it ideal for quickly checking many binaries.

**The process typically involves:**

1.  **Environment Setup:** EMBA creates a temporary, isolated environment (a `chroot` or `jchroot` jail) containing the target binary and its necessary libraries.
2.  **Emulator Injection:** The appropriate `qemu-*-static` binary (e.g., `qemu-arm-static` for ARM binaries) is copied into this isolated environment.
3.  **Execution:** Each firmware binary is then executed within this environment, with various parameters (like `--version`, `-h`, etc.) to see its output.
4.  **Error Analysis (`strace`):** If a binary fails to run, EMBA can re-run it with `strace` (a tool that logs system calls). This helps identify if the binary is looking for missing files or configurations, which EMBA can then try to "fix" by copying those files into the emulation environment. This is critical for making more binaries executable.
5.  **Output Capture:** All output from the emulated binaries is captured and saved for later analysis (like extracting version numbers).

### Under the Hood: `S115_usermode_emulator.sh`

The `modules/S115_usermode_emulator.sh` module is responsible for orchestrating the user-mode emulation.

*   **`copy_firmware()`**: Before performing user-mode emulation, EMBA makes a local copy of the extracted firmware filesystem. This ensures that any changes or temporary files generated during emulation don't affect the original extracted firmware image, which other static analysis modules might still be using.

    ```bash
    # Snippet from S115_usermode_emulator.sh (simplified)
    # Check if enough disk space to create a copy
    if [[ "${lFREE_SPACE}" -gt "${lNEEDED_SPACE}" ]]; then
      print_output "[*] Create a firmware backup for emulation ..."
      cp -pri "${EMULATION_PATH_BASE}" "${LOG_PATH_MODULE}"/firmware # Copy the entire extracted firmware
      EMULATION_PATH_BASE="${LOG_PATH_MODULE}"/firmware # Use the copy
    else
      print_output "[!] WARNING: Not enough disk space, using original firmware."
    fi
    ```
    This function ensures a safe, isolated working copy for user-mode emulation.

*   **`setup_jchroot()` / `setup_chroot()`**: These functions prepare the isolated root environment. `chroot` (change root) is a standard Linux command that changes the apparent root directory for a running process. `jchroot` is a more secure version. This prevents the emulated binary from accessing or harming your host system.

    ```bash
    # Snippet from S115_usermode_emulator.sh (simplified)
    if command -v jchroot > /dev/null; then
      export CHROOT="jchroot"
      print_output "[*] Using ${ORANGE}jchroot${NC} for secure chroot environments."
    elif command -v chroot > /dev/null; then
      export CHROOT="chroot"
      print_output "[*] Using ${ORANGE}chroot${NC} for chroot environments."
    fi
    ```
    This sets up the isolation mechanism, picking `jchroot` if available for better security.

*   **`prepare_emulator()`**: This function copies the specific QEMU user-mode emulator (`qemu-arm-static`, `qemu-mips-static`, etc.) into the chroot environment and also creates necessary device nodes (`/dev/null`, `/dev/console`) that binaries often expect.

    ```bash
    # Snippet from S115_usermode_emulator.sh (simplified)
    local lR_PATH="${1:-}" # The root directory of the isolated firmware copy
    local lEMULATOR="${2:-}" # The specific QEMU user-mode binary

    if ! command -v "${lEMULATOR}" > /dev/null ; then
      print_output "[!] Qemu package not installed!" # Check if QEMU is available on host
      exit 1
    else
      cp "$(command -v "${lEMULATOR}")" "${lR_PATH}" # Copy QEMU to the isolated environment
    fi
    # Create necessary /dev entries inside the isolated environment
    mknod -m 666 "${lR_PATH}"/dev/null c 1 3
    # ... more mknod calls ...
    ```
    This ensures that the correct QEMU binary and essential device files are accessible within the isolated environment.

*   **`emulate_strace_run()`**: This crucial function runs the binary under `strace` (a Linux tool that tracks system calls). It helps identify what files the binary tries to open that might be missing in the emulated environment. If missing files are found, EMBA tries to locate them in the original extracted firmware and copies them to the correct location in the emulation environment, making more binaries runnable.

    ```bash
    # Snippet from S115_usermode_emulator.sh (simplified)
    # Run QEMU with strace to identify missing files (errno=2)
    timeout --preserve-status --signal SIGINT 2 "${CHROOT}" "${OPTS[@]}" "${R_PATH}" -- ./"${lEMULATOR}" --strace "${BIN_}" >> "${lLOG_FILE_STRACER}" 2>&1 &
    # ... then parse lLOG_FILE_STRACER for "errno=2" (file not found)
    mapfile -t MISSING_AREAS_ARR < <(grep -a "open.*errno=2\ " "${lLOG_FILE_STRACER}" | cut -d\" -f2)
    for MISSING_AREA in "${MISSING_AREAS_ARR[@]}"; do
      # If the missing file is found elsewhere in the firmware, copy it
      lFILENAME_FOUND=$(find "${EMULATION_PATH_BASE}" -name "$(basename "${MISSING_AREA}")" | head -1)
      if [[ -n "${lFILENAME_FOUND}" ]]; then
        mkdir -p "${R_PATH}""$(dirname "${MISSING_AREA}")"
        cp -L "${lFILENAME_FOUND}" "${R_PATH}""$(dirname "${MISSING_AREA}")"
      fi
    done
    ```
    This loop automatically tries to "heal" the emulated filesystem by providing missing files that programs need to run successfully.

*   **`emulate_binary()`**: This is the core function that executes each identified binary with QEMU, trying different command-line parameters (like `-v`, `--help`) and log the complete output of the running binary to finally get needed version details.

    ```bash
    # Snippet from S115_usermode_emulator.sh (simplified)
    # Get optimal CPU config (from previous 'run_init_test')
    local lCPU_CONFIG="$(grep -a "CPU_CONFIG_det" "${LOG_PATH_MODULE}""/qemu_init_""${lBIN_EMU_NAME}"".txt" | cut -d\; -f2 | head -1)"

    # Iterate over common parameters to get binary output
    for lPARAM in ("" "-v" "-V" "-h" "--help" "--version"); do
      # Execute binary in chroot with QEMU and parameters
      timeout --preserve-status --signal SIGINT "${QRUNTIME}" "${CHROOT}" "${OPTS[@]}" "${lR_PATH}" -- ./"${lEMULATOR}" -cpu "${lCPU_CONFIG}" "${lBINARY_MIN_PATH}" "${lPARAM}" &>> "${lLOG_FILE_BIN}" || true &
    done
    ```
    This function tries to elicit information from the binary by running it with various common command-line arguments.

The outputs from `S115` (captured logs for each binary) are further processed by **`S116_qemu_version_detection.sh`** to extract version strings, which are finally fed into EMBA's SBOM and vulnerability aggregation engine:

![image](https://github.com/user-attachments/assets/0c1e6d33-48c2-48d7-9e5f-053d8f607f6d)

To get a better overview of the emulation capabilities of EMBA proceed with [Chapter 4: Booting up the system via System emulation](The-EMBA-book-‐-Chapter-4%3A-System-Emulation).
