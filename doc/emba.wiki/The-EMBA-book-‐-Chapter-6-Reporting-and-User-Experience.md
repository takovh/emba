# Chapter 6: Reporting & User Experience

Welcome back, firmware detectives! By now, EMBA has dug deep into your firmware: it has extracted all the files, meticulously checked their code and configurations, and even observed some parts behaving in a controlled environment. You've gathered a tremendous amount of raw data!

But what do you do with this mountain of information? How do you answer critical questions like: "What are the most important security findings?" or "Where exactly are these issues located?" You wouldn't just dump a pile of raw notes on a stakeholder.

This is where EMBA's **Reporting & User Experience** features come in! They are like EMBA's "presentation layer," turning all that raw, technical data into a clear, understandable story. Imagine you're a detective who has just solved a complex case. You've gathered tons of evidence, analyzed fingerprints, and interviewed suspects. Now, you need to present all this to the "jury" (your team or stakeholders) in a way that's clear, convincing, and easy to understand. EMBA automates this crucial step, providing you with a polished "case file" and keeping you informed throughout the investigation.

This abstraction focuses on making EMBA's findings clear and actionable. It gathers all the raw data from various analysis modules and compiles them into a comprehensive, easy-to-understand report, often in an interactive HTML format. It also manages user feedback through desktop notifications and a live terminal status bar, keeping you informed throughout the analysis process.

## Key Concepts: Your Report and Your Feedback

EMBA’s reporting and user experience features are designed to give you both a polished summary of findings and real-time updates during the analysis.

### 1. Comprehensive HTML Reports: Your Final Case File

Think of EMBA's main report as your carefully compiled and professionally presented "case file." It's an interactive HTML document that brings together all the discoveries from every analysis module:

*   **Vulnerability Findings:** Detailed lists of CVEs, their severity, and links to external databases or proof-of-concept exploits.
*   **Software Bill of Materials (SBOM):** The complete inventory of all software components, their versions, and licenses.
*   **Configuration Issues:** Weak permissions, hardcoded credentials, insecure network settings, and more.
*   **Binary Protections:** A summary of security features found (or missing) in executables.
*   **System Details:** Detected operating system, architecture, and other general information about the firmware.

![alt](images/report_usage.jpg)

This report is interactive, allowing you to click on links to jump to specific sections, view detailed logs, or even download related files.

### 2. Live Terminal Status Bar: Your Real-time Dashboard

During a long analysis, you don't want to just stare at a blank screen. EMBA provides a dynamic status bar at the bottom of your terminal. This is like the dashboard of a spy car, showing you real-time metrics:

*   **System Load:** CPU, memory, and disk usage so you know how hard EMBA is working.
*   **Overall Progress:** How long EMBA has been running and how many modules have completed.
*   **Current Activity:** Which module EMBA is currently running.
*   **Errors:** A quick count of any errors encountered.

![image](https://github.com/user-attachments/assets/6c460a79-80e1-4381-bd97-d62b2c3f12d7)

### 3. Desktop Notifications: Alerts from the Field

For important events, such as the completion of a long analysis, EMBA can send you desktop notifications (if your system supports them). This is like getting a quick alert from your team in the field – you don't need to constantly check the terminal; EMBA will ping you when something significant happens.

## How to Use It: Mostly Automatic!

The best part about EMBA's reporting and user experience features is that **they work automatically** on most firmware analysis scans!

EMBA will automatically:
*   **Generate the HTML report:** Once the analysis is complete, a comprehensive HTML report will be created. You can find it in your log directory, typically at `logs/<firmware_name>/html_report/index.html`. Just open this file in your web browser!
*   **Display the live status bar:** As long as your terminal window is large enough, the status bar will appear automatically at the bottom, providing real-time updates without you needing to do anything.
*   **Send desktop notifications:** For key events, EMBA will trigger system notifications.

## Under the Hood: Crafting the Report

EMBA's reports are a culmination of all its hard work. Let's look at the key components that bring this "case file" to life.

### The Master Aggregator (`modules/F50_base_aggregator.sh`)

Imagine the `F50_base_aggregator.sh` module as the "lead detective" or "editor-in-chief." Its main job is to collect all the pieces of evidence (analysis results) from various other modules and organize them into a coherent narrative for the final report.

It runs towards the end of the EMBA process and calls a series of internal functions, each responsible for gathering specific types of data:

*   `output_overview()`: Gathers general firmware details (vendor, version, EMBA command).
*   `output_details()`: Summarizes static and dynamic analysis findings (file counts, script vulnerabilities, emulation success).
*   `output_config_issues()`: Reports on weak permissions, password hashes, certificate issues, and other misconfigurations.
*   `output_binaries()`: Details binary protections and weak function usages like `strcpy`.
*   `output_cve_exploits()`: Presents the SBOM and all identified CVEs and exploits.

Each of these functions reads data from the individual log files (CSV, JSON, and raw text logs) generated by modules like [Static Analysis Modules](04_static_analysis_modules_.md) (e.g., `S12_binary_protection.sh`, `S40_weak_perm_check.sh`) and [SBOM & Vulnerability Aggregation](06_sbom___vulnerability_aggregation_.md) (e.g., `F17_cve_bin_tool.sh`).

Here's a simplified look at how `F50_base_aggregator.sh` might call one of its data-gathering functions:

```bash
# Simplified from modules/F50_base_aggregator.sh

F50_base_aggregator() {
  # Initialize logging for this module
  module_log_init "${FUNCNAME[0]}"
  module_title "Final aggregator"
  pre_module_reporter "${FUNCNAME[0]}"

  # Call function to get all data from other modules
  get_data

  # Call functions to output different sections of the report
  output_overview     # General info
  output_details      # Detailed analysis results
  output_config_issues # Configuration problems
  output_binaries     # Binary analysis
  output_cve_exploits # SBOM and CVEs

  module_end_log "${FUNCNAME[0]}" 1
}

# The get_data() function is responsible for populating global variables
# like CVE_COUNTER or S20_SHELL_VULNS by reading various log files.
```
The `F50_base_aggregator` combines all the information into a single, cohesive view.

### The HTML Converter (`helpers/helpers_emba_html_generator.sh`)

Once `F50_base_aggregator.sh` has gathered all the information and formatted it into consolidated log files, the `helpers/helpers_emba_html_generator.sh` script steps in. This is the "graphic designer" of the team. Its job is to take the plain text output from EMBA's internal logs and transform it into a beautiful, interactive HTML report that's easy to read in a web browser.

It does this by:
1.  **Converting ANSI Colors to HTML:** EMBA's terminal output uses special "ANSI escape codes" to add colors (like red for warnings, green for success). This helper script replaces these codes with HTML `<span>` tags, so the colors appear correctly in the web report.
2.  **Adding Hyperlinks:** It automatically scans the text for URLs, CVE IDs, Exploit-DB IDs, and internal references (like links to other modules' reports) and converts them into clickable HTML `<a>` tags.
3.  **Structuring Content:** It adds HTML tags for paragraphs (`<pre>`), headings, and horizontal rules to make the report readable and organized.
4.  **Embedding Assets:** It copies screenshots, graphs, and other supplementary files into the report directory and links them.

Let's look at simplified examples of how it converts plain text into rich HTML:

**1. Adding Colors:**

```bash
# Simplified from helpers/helpers_emba_html_generator.sh
# lCOLOR_FILE is the path to a plain text log file
# SPAN_RED and SPAN_END are HTML tags like "<span class=\"red\">" and "</span>"

add_color_tags() {
  local lCOLOR_FILE="${1:-}"
  # Replace terminal color codes with HTML span tags
  sed -i -E \
    -e "s@\\x1b\\[31m@${SPAN_RED}@g" \
    -e "s@\\x1b\\[32m@${SPAN_GREEN}@g" \
    -e "s@\\x1b\\[0m@${SPAN_END}@g" \
    "${lCOLOR_FILE}" || true
}
```
This snippet shows how special `sed` commands are used to find patterns representing terminal color codes (like `\x1b[31m` for red) and replace them with the corresponding HTML `<span>` tags defined earlier in the script. The `SPAN_END` tag (`\x1b[0m`) closes the color.

**2. Adding Links:**

```bash
# Simplified from helpers/helpers_emba_html_generator.sh
# lLINK_FILE is the path to a plain text log file
# LINK and LINK_END are HTML <a> and </a> tags for external URLs
# CVE_LINK is HTML <a> tag specifically for CVEs

add_link_tags() {
  local lLINK_FILE="${1:-}"

  # Find common web links (http/https) and wrap them in HTML <a> tags
  sed -i -E \
    -e 's@((https?|ftp|file):\/\/[^[:space:]]+)@'"${LINK}"'\\1'"${LINK_END}"'@g' \
    "${lLINK_FILE}" || true

  # Similarly, replace CVE IDs with links to the NVD database
  sed -i -E \
    -e 's@(CVE-[0-9]{4}-[0-9]{4,7})@'"${CVE_LINK}"'\\1'"${LINK_END}"'@g' \
    "${lLINK_FILE}" || true
}
```
This `add_link_tags` function uses similar `sed` commands to identify URLs and CVE IDs. For example, it finds any string starting with `CVE-` followed by numbers and replaces it with a clickable link to the NVD (National Vulnerability Database) website, using `CVE_LINK` as the template.

Finally, the `generate_report_file` function (also in `helpers_emba_html_generator.sh`) orchestrates the overall process, combining a base HTML template with the processed log content and ensuring all links and styles are correctly applied.

## Under the Hood: Real-time User Experience

EMBA's user experience goes beyond just the final report. It keeps you engaged during the entire analysis process.

### The Status Bar (`helpers/helpers_emba_status_bar.sh`)

The `helpers/helpers_emba_status_bar.sh` script is responsible for creating and updating the interactive status bar at the bottom of your terminal. It's like having a dedicated "operations dashboard" right there in your command line.

It uses special terminal escape codes to draw boxes, display text, and update numbers without interfering with the scrolling output of the main log.

**1. Drawing the Boxes:**

```bash
# Simplified from helpers/helpers_emba_status_bar.sh
# lLINES: total lines in terminal; lBOX_L: left position; lBOX_W: width; lBOX_TITLE: title text

draw_box() {
  local lLINES="${1:-}" # Total lines in terminal
  local lBOX_W="${2:-0}" # Box width
  local lBOX_TITLE="${3:-}" # Box title (e.g., "SYSTEM LOAD")
  local lBOX_L="${4:-0}" # Left column position

  # Move cursor, print top border with title
  printf '\e[%s;%sf┌%s%s┐\n' "$((lLINES - 4))" "${lBOX_L}" "\033[1m${lBOX_TITLE}\033[0m" "$(repeat_char "─" "$((lBOX_W - ${#lBOX_TITLE} - 2))")"
  # Print middle lines (empty for now)
  printf '\e[%s;%sf│%s│\n' "$((lLINES - 3))" "${lBOX_L}" "$(repeat_char " " "$((lBOX_W - 2))")"
  printf '\e[%s;%sf│%s│\n' "$((lLINES - 2))" "${lBOX_L}" "$(repeat_char " " "$((lBOX_W - 2))")"
  printf '\e[%s;%sf│%s│\n' "$((lLINES - 1))" "${lBOX_L}" "$(repeat_char " " "$((lBOX_W - 2))")"
  # Print bottom border
  printf '\e[%s;%sf└%s┘\n' "${lLINES}" "${lBOX_L}" "$(repeat_char "─" "$((lBOX_W - 2))")"
}
```
This `draw_box` function uses `printf` with `\e[` (ESC key) sequences to control the cursor position (`%s;%sf`) and bold text (`\033[1m`). It draws a simple ASCII box structure with a title.

**2. Updating the Metrics:**

```bash
# Simplified from helpers/helpers_emba_status_bar.sh
# Reads system metrics and formats them for display in the status bar.

update_box_system_load() {
  # Get CPU usage (example using vmstat)
  local cpu_usage=$(vmstat 1 2 | tail -1 | awk '{print 100 - $15}')
  # Get memory usage (example using free)
  local mem_usage=$(LANG=en free | grep Mem | awk '{print int($3/$2 * 100)}')
  # Get disk usage (example using df)
  local disk_usage=$(df "${LOG_DIR}" | tail -1 | awk '{print substr($5, 1, length($5)-1)}')

  # Format usage strings (e.g., with colored bars) using another helper
  local cpu_str=$(system_load_util_str "${cpu_usage}" 0)
  local mem_str=$(system_load_util_str "${mem_usage}" 1)
  local disk_str=$(system_load_util_str "${disk_usage}" 2)

  # `printf` with `\e[s` (save cursor), `\e[u` (restore cursor)
  # updates specific lines in the status bar without disrupting main output.
  printf '\e[s\e[%s;3f%s\e[%s;3f%s\e[%s;3f%s\e[u' \
    "$((lLINES - 3))" "${cpu_str}" \
    "$((lLINES - 2))" "${mem_str}" \
    "$((lLINES - 1))" "${disk_str}"
}
```
The `update_box_system_load` function (and similar ones for status and modules) runs continuously in the background. It periodically collects system metrics (like CPU, memory, disk usage) using standard Linux commands (`vmstat`, `free`, `df`). It then uses `printf` with precise cursor positioning (`\e[s` to save current cursor position, `\e[u` to restore) to update the text *inside* the pre-drawn boxes without making the main terminal scroll.

The `initial_status_bar` function is called once at the beginning of the EMBA run to set up the status bar, calculate box sizes based on your terminal width, and start the background update processes.

### Desktop Notifications

While EMBA's core doesn't include a dedicated graphical notification system, it leverages common Linux utilities like `notify-send` (often part of `libnotify-bin`) to trigger pop-up messages. When a significant event occurs (e.g., analysis finished, a critical vulnerability is found), EMBA can execute a simple command like:

```bash
notify-send "EMBA Analysis Complete!" "Firmware analysis for my_device.bin has finished. Check the report!"
```
This command sends a notification to your desktop environment, appearing as a small pop-up in the corner of your screen, letting you know the status of your analysis without needing to constantly check the terminal.

## Conclusion

EMBA's **Reporting & User Experience** features are the final touch, transforming complex security analysis into clear, actionable intelligence and providing real-time feedback during the process. By automatically generating comprehensive HTML reports and providing a dynamic terminal status bar with desktop notifications, EMBA ensures that whether you're actively monitoring the scan or reviewing the final results, you have all the information you need in a user-friendly format. This abstraction makes your journey as a firmware detective as informative and efficient as possible.