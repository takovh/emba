
## `*S13_weak_func_check`

这是EMBA中一个关键的**二进制安全分析模块**，专门用于检测嵌入式固件中潜在的危险函数和不安全的编码模式。

---

### **1. 模块定位与核心功能**

**主要目标**

- **静态分析**二进制文件中的安全敏感函数
    
- **识别危险函数调用**（如strcpy、gets、system等）
    
- **检测不安全模式**（格式化字符串漏洞、竞争条件等）
    
- **评估整体安全状况**，为动态测试提供方向
    

**在测试流程中的位置**

- 通常在固件解压和基本分析之后执行
    
- 依赖前序模块：
    
    - 固件提取和文件系统分析
        
    - 二进制保护机制检测
        
    
- 为后续模块提供输入：
    
    - 凭证暴力破解
        
    - 动态符号执行
        
    - Web应用程序分析
        
    

---

### **2. 检测的危险函数类别**

|风险类别|示例函数|CWE关联|风险描述|
|---|---|---|---|
|**缓冲区溢出**​|`strcpy`, `strcat`, `gets`, `sprintf`|CWE-120, CWE-121|无边界检查的字符串操作|
|**格式化字符串**​|`printf`, `sprintf`, `syslog`|CWE-134|用户控制格式字符串|
|**命令注入**​|`system`, `popen`, `exec*`|CWE-78|未过滤的命令执行|
|**路径遍历**​|`open`, `fopen`, `chdir`|CWE-22|相对路径操作|
|**竞争条件**​|`access`, `stat`, `tempnam`|CWE-367|TOCTOU漏洞|
|**内存管理**​|`malloc`, `free`, `realloc`|CWE-415, CWE-416|双重释放、UAF|
|**加密弱函数**​|`rand`, `srand`, `crypt`|CWE-327|弱随机性/加密|
|**信息泄露**​|`strerror`, `perror`|CWE-209|敏感信息泄露|
|**整数处理**​|`atoi`, `atol`, `scanf`|CWE-190, CWE-197|整数溢出/截断|

---

### **3. 技术架构与检测方法**

**3.1 多层检测框架**

```
S13_weak_func_check
├── 第1层：符号表扫描 (objdump/readelf)
├── 第2层：字符串常量分析 (strings/grep)
├── 第3层：反汇编模式匹配 (objdump -d)
├── 第4层：调用图分析 (cflow/radare2)
├── 第5层：上下文敏感分析
└── 第6层：启发式规则评估
```

**3.2 核心检测逻辑**

```
# 检测strcpy使用的简化逻辑
check_strcpy_usage() {
    local binary="$1"
    
    # 方法1：符号表查找
    if objdump -T "$binary" 2>/dev/null | grep -q "strcpy"; then
        echo "[+] Found strcpy in symbol table"
    fi
    
    # 方法2：字符串引用查找
    if strings "$binary" | grep -q "strcpy"; then
        echo "[+] Found strcpy string reference"
    fi
    
    # 方法3：反汇编模式匹配
    # 查找 call strcpy 或 bl strcpy
    if objdump -d "$binary" 2>/dev/null | grep -q "call.*strcpy\|bl.*strcpy"; then
        echo "[+] Found strcpy call in disassembly"
    fi
    
    # 方法4：PLT/GOT条目检查
    if readelf -r "$binary" 2>/dev/null | grep -q "strcpy"; then
        echo "[+] Found strcpy in relocation entries"
    fi
}
```

**3.3 架构特定处理**

```
# ARM架构检测
check_arm_binary() {
    local binary="$1"
    
    # ARM调用约定：bl <address>
    objdump -d "$binary" | \
        grep -E "bl\s+[0-9a-f]+\s+.*<.*strcpy.*>" | \
        while read line; do
            address=$(echo "$line" | awk '{print $1}')
            echo "ARM call to strcpy at: $address"
        done
}

# MIPS架构检测
check_mips_binary() {
    # MIPS通过t9寄存器调用
    objdump -d "$binary" | \
        grep -E "jalr\s+\$t9\|jal\s+.*strcpy" | \
        # 进一步分析跳转目标
        analyze_mips_call "$binary"
}
```

---

### **4. 详细执行流程**

**阶段1：二进制文件收集**

```
# 从提取的文件系统中获取所有ELF文件
find "$FIRMWARE_PATH" -type f -executable -exec file {} \; | \
    grep "ELF.*executable" | cut -d: -f1 > "$ELF_LIST"
```

**阶段2：危险函数数据库加载**

```
# 内置危险函数定义
DANGEROUS_FUNCS=(
    "strcpy:CWE-120:Buffer Overflow"
    "gets:CWE-242:Use of Inherently Dangerous Function"
    "sprintf:CWE-134:Format String"
    "system:CWE-78:OS Command Injection"
    "rand:CWE-327:Use of a Broken or Risky Cryptographic Algorithm"
    # ... 100+ 函数定义
)
```

**阶段3：多层分析**

```
analyze_binary() {
    local binary="$1"
    
    # 1. 基本文件信息
    file_type=$(file "$binary")
    arch=$(echo "$file_type" | grep -o "ARM\|MIPS\|x86\|PowerPC")
    
    # 2. 保护机制检查（依赖S12结果）
    check_protections "$binary"
    
    # 3. 符号分析
    analyze_symbols "$binary"
    
    # 4. 字符串分析
    analyze_strings "$binary"
    
    # 5. 反汇编分析
    analyze_disassembly "$binary"
    
    # 6. 交叉引用分析
    analyze_xrefs "$binary"
}
```

**阶段4：风险评分与优先级**

```
calculate_risk_score() {
    local func="$1"
    local count="$2"
    local context="$3"
    
    # 基础风险分数
    case "$func" in
        "strcpy") base_score=8 ;;
        "gets") base_score=9 ;;
        "system") base_score=7 ;;
        "sprintf") base_score=6 ;;
        *) base_score=5 ;;
    esac
    
    # 考虑调用次数
    if [ "$count" -gt 5 ]; then
        score=$((base_score + 2))
    elif [ "$count" -gt 2 ]; then
        score=$((base_score + 1))
    else
        score=$base_score
    fi
    
    # 上下文调整（例如在root权限的二进制中）
    if echo "$context" | grep -q "setuid\|root"; then
        score=$((score + 3))
    fi
    
    echo "$score"
}
```

---

### **5. 输出格式与报告**

**详细报告结构**

```
========================================================================
S13 - Weak Function Check Results
========================================================================
[+] Analyzing: /usr/bin/vulnerable_app
  ├─ Architecture: ARM 32-bit (little-endian)
  ├─ Protection: NX enabled, No Canary, No PIE
  ├─ Total dangerous functions: 12
  └─ Risk score: 78/100 (HIGH)

[!] CRITICAL FINDINGS (score >= 9):
    ┌──────────────┬─────────┬──────────┬─────────────────────────────┐
    │ Function     │ Calls   │ Address  │ Risk Description           │
    ├──────────────┼─────────┼──────────┼─────────────────────────────┤
    │ gets         │ 2       │ 0x080485 │ CWE-242: No bounds check  │
    │ system       │ 5       │ 0x080492 │ CWE-78: Command injection │
    └──────────────┴─────────┴──────────┴───────────────────────────┘

[+] MEDIUM FINDINGS (score 5-8):
    ┌──────────────┬─────────┬──────────┬─────────────────────────────┐
    │ strcpy       │ 8       │ 0x0804a1 │ CWE-120: Buffer overflow  │
    │ sprintf      │ 3       │ 0x0804b2 │ CWE-134: Format string    │
    └──────────────┴─────────┴──────────┴─────────────────────────────┘

[~] LOW FINDINGS (score < 5):
    ┌──────────────┬─────────┬──────────┬─────────────────────────────┐
    │ rand         │ 1       │ 0x0804c3 │ CWE-327: Weak randomness  │
    └──────────────┴─────────┴──────────┴─────────────────────────────┘

[+] CONTEXT ANALYSIS:
    ├─ Called from main() at 0x0804845
    ├─ Input source: stdin (unfiltered)
    └─ Privilege level: root (setuid bit set)

[+] EXPLOIT MITIGATION ANALYSIS:
    ├─ Stack canary: NOT FOUND
    ├─ ASLR (PIE): DISABLED
    ├─ NX/DEP: ENABLED
    └─ RELRO: PARTIAL

[+] RECOMMENDATIONS:
    1. Replace gets() with fgets() with proper bounds checking
    2. Use execve() with argument arrays instead of system()
    3. Enable full RELRO and PIE for ASLR protection
    4. Add stack canaries via -fstack-protector-all
```

**JSON输出结构**

```
{
  "module": "S13_weak_func_check",
  "binary": "/usr/bin/vulnerable_app",
  "architecture": "armel",
  "findings": [
    {
      "function": "gets",
      "call_count": 2,
      "addresses": ["0x08048510", "0x080485a4"],
      "risk_level": "CRITICAL",
      "cwe_id": "CWE-242",
      "description": "Use of inherently dangerous function 'gets'",
      "exploit_scenarios": [
        "Buffer overflow leading to arbitrary code execution",
        "Control of instruction pointer (EIP/RIP)"
      ],
      "remediation": "Replace with fgets() with proper bounds checking",
      "score": 9.5
    }
  ],
  "summary": {
    "total_functions": 12,
    "critical_count": 2,
    "high_count": 4,
    "medium_count": 3,
    "low_count": 3,
    "overall_risk": 78
  },
  "metadata": {
    "analysis_time": "12.4s",
    "binary_size": "24576 bytes",
    "analyzer_version": "1.2.3"
  }
}
```

---

### **6. 高级检测技术**

**6.1 上下文敏感分析**

```
analyze_context() {
    local binary="$1"
    local func="$2"
    local address="$3"
    
    # 检查调用前代码（前向切片）
    echo "=== Context before call to $func at $address ==="
    objdump -d "$binary" | \
        awk -v addr="$address" -v range=20 '
        BEGIN {print_it=0}
        $1 ~ /^[0-9a-f]+:$/ {
            current=$1
            gsub(":", "", current)
            if(current == addr) print_it=1
            if(print_it && (NR > print_start+range)) exit
        }
        print_it {print}
        ' | head -30
    
    # 检查调用约定
    check_calling_convention "$binary" "$address"
    
    # 检查参数来源
    trace_parameter_source "$binary" "$address"
}
```

**6.2 数据流分析（简单版本）**

```
trace_strcpy_usage() {
    local binary="$1"
    
    # 查找所有strcpy调用
    objdump -d "$binary" | grep -B5 "call.*strcpy" | \
    while read line; do
        # 检查源参数
        if echo "$line" | grep -q "mov.*\[ebp-0x.*\],.*eax"; then
            echo "[!] Possible stack-based buffer as source"
        fi
        
        # 检查目标参数大小
        if echo "$line" | grep -q "lea.*\[ebp-0x.*\],.*edx"; then
            buffer_size=$(echo "$line" | sed 's/.*ebp-0x//' | cut -c1-2)
            if [ "$((0x$buffer_size))" -lt 32 ]; then
                echo "[!] Small buffer detected: 0x$buffer_size bytes"
            fi
        fi
    done
}
```

**6.3 模式匹配规则**

```
# 危险模式：memcpy with size from user input
check_memcpy_overflow() {
    objdump -d "$binary" | \
    awk '
    /call.*memcpy/ {
        # 查找前几条指令中的size参数
        for(i=1; i<=10; i++) {
            if(prev[i] ~ /mov.*eax,\[ebp-0x/) {
                print "[!] Possible user-controlled memcpy size at " $1
            }
        }
    }
    {for(i=9; i>=2; i--) prev[i]=prev[i-1]; prev[1]=$0}
    '
}
```

---

### **7. 配置与优化**

**配置文件示例**

```
[S13_weak_func_check]
# 分析深度
analysis_depth = 3              # 1=基本, 2=详细, 3=深度
max_file_size = 10485760        # 10MB限制
timeout_per_binary = 30         # 每个二进制超时(秒)

# 风险阈值
critical_score = 9.0
high_score = 7.0
medium_score = 5.0

# 架构特定设置
enable_arm_analysis = true
enable_mips_analysis = true
enable_x86_analysis = true

# 输出选项
generate_json = true
generate_html = false
verbose_output = true
color_output = true

# 自定义规则
custom_rules_file = /etc/emba/custom_rules.txt
```

**性能优化技巧**

```
# 1. 并行处理
find "$FIRMWARE_PATH" -name "*.elf" -o -name "*.bin" | \
    xargs -P 4 -I {} ./check_binary.sh {}   # 4个并行进程

# 2. 缓存机制
if [ -f "$CACHE_FILE" ] && [ "$binary" -ot "$CACHE_FILE" ]; then
    use_cache "$binary"
else
    analyze_and_cache "$binary"
fi

# 3. 增量分析
analyze_only_newer_files() {
    find "$FIRMWARE_PATH" -newer "$LAST_RUN_FILE" -type f -executable
}
```

---

### **8. 实际应用案例**

**案例1：路由器的setuid二进制分析**

```
# 查找所有setuid二进制
find / -type f -perm -4000 -exec ./emba_s13_module.sh {} \;

# 输出示例
[!] CRITICAL: /usr/bin/backup_utility
    ├─ Uses gets() to read backup password
    ├─ Calls system() with user-controlled data
    ├─ setuid root - full compromise possible
    └─ No stack protection enabled
```

**案例2：IP摄像头固件分析**

```
分析结果：
- 主守护进程（/usr/bin/camd）包含strcpy调用12处
- Web接口CGI（/usr/www/cgi-bin/*）使用system()执行命令
- 固件更新工具使用sprintf构建路径，可能路径遍历
- 认证模块使用rand()生成会话ID，可预测
```

**案例3：工业控制器PLC**

```
# 专用架构分析
./emba --architecture=ppc --endian=big \
       --weak-func-check=aggressive \
       -f plc_firmware.bin
```

---

### **9. 限制与应对策略**

**已知限制**

1. **静态分析局限**：
    
    - 无法分析动态加载的函数
        
    - 间接调用（函数指针）难以追踪
        
    - 内联汇编可能被遗漏
        
    
2. **误报/漏报**：
    
    - 安全的使用可能被标记为危险
        
    - 混淆/加壳代码难以分析
        
    - 自定义分配函数可能漏报
        
    

**降低误报策略**

```
# 启发式规则：检查缓冲区大小
is_safe_strcpy() {
    local binary="$1"
    local address="$2"
    
    # 如果源是字符串字面量且长度已知
    if strings_near_call "$binary" "$address" | \
       grep -q "strcpy.*%[0-9]d.*s"; then
        return 0  # 可能是安全的
    fi
    
    # 检查前是否有边界检查
    if has_bound_check "$binary" "$address"; then
        return 0
    fi
    
    return 1  # 不安全的
}
```

**扩展检测能力**

```
# 集成外部工具
integrate_external_tools() {
    # 使用IDA Pro的idat进行深度分析
    if command -v idat64 &>/dev/null; then
        idat64 -A -S"weak_func_check.idc" "$binary"
    fi
    
    # 使用Ghidra进行反编译
    if command -v analyzeHeadless &>/dev/null; then
        analyzeHeadless /tmp "$binary" \
            -import "$binary" \
            -postScript WeakFuncSearch.java
    fi
    
    # 使用angr进行符号执行
    if command -v python3 &>/dev/null; then
        python3 -c "import angr; p=angr.Project('$binary')"
    fi
}
```

---

### **10. 自定义规则开发**

**添加自定义危险模式**

```
# 在custom_rules.txt中定义
[Custom_Rule:Weak_Crypto]
pattern = "MD5Init|MD5Update|MD5Final|DES_set_key"
description = "Use of weak cryptographic algorithms (MD5/DES)"
cwe_id = "CWE-327"
risk_level = "HIGH"
remediation = "Use SHA-256 or AES instead"

[Custom_Rule:Hardcoded_Creds]
pattern = "admin:admin|root:12345|guest:guest"
description = "Hardcoded default credentials"
cwe_id = "CWE-798"
risk_level = "CRITICAL"
```

**自定义分析脚本**

```
#!/bin/bash
# custom_analyzer.sh
analyze_custom_patterns() {
    local binary="$1"
    
    # 检测硬编码密钥
    strings "$binary" | \
        grep -E "[A-F0-9]{32,128}" | \
        while read line; do
            echo "[!] Possible hardcoded key: $line"
        done
    
    # 检测调试符号
    if nm "$binary" 2>/dev/null | grep -q "DEBUG"; then
        echo "[!] Debug symbols present in release build"
    fi
}
```

---

### **总结**

**S13_weak_func_check**是EMBA中**二进制安全分析的核心模块**，具有以下特点：

**核心价值**

1. **早期预警**：无需执行代码即可发现高危漏洞
    
2. **全面覆盖**：支持多种架构和ABI
    
3. **风险评估**：量化漏洞严重程度
    
4. **可操作报告**：提供具体的修复建议
    

**最佳实践**

1. **组合使用**：与动态分析（S24）和模糊测试（L25）结合
    
2. **误报验证**：人工审查关键发现
    
3. **持续更新**：维护危险函数数据库和检测规则
    
4. **环境考虑**：考虑嵌入式系统的资源限制
    

**发展趋势**

- 集成AI/ML进行模式识别
    
- 支持更多架构（RISC-V、Tensilica等）
    
- 与CI/CD流水线集成
    
- 云原生固件分析支持
    

这个模块是物联网设备安全评估的关键环节，能够快速识别最可能被利用的代码模式，帮助安全团队优先处理高风险问题。

