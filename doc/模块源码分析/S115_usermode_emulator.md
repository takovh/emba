
## `S115_usermode_emulator`

`S115_usermode_emulator` 是 **EMBA（Embedded Linux Analyzer）** 中一个**偏偏偏“高级/重型”的动态分析模块**，主要用于：

> **在宿主机上通过 _用户态仿真_ 的方式运行固件中的可执行程序，从而发现静态分析无法发现的漏洞与行为。**

下面从**定位、做什么、怎么做、输入输出、常见风险**几个角度给你一个**源码级可落地的介绍**。

---

### 一、模块在 EMBA 中的定位

**模块编号：S115**  
**类别：Static → Dynamic 边界模块（Usermode Emulation）**

它通常在以下条件下被调度：

- 已识别出 **CPU 架构（ARM / MIPS / x86 / …）**
    
- 固件是 **Linux 用户态程序**
    
- 目标 binary **可在 QEMU user-mode 下运行**
    
- 扫描 profile 允许执行动态模拟
    

> ⚠️ 与 `S120/S130` 这种“全系统仿真”不同，  
> **S115 不启动完整系统，只跑单个 ELF**

---

### 二、S115 模块主要做什么？

一句话总结：

> **用 QEMU user-mode + chroot/LD 伪环境，执行固件中的 ELF 程序，并监控其行为**

具体目标包括：

1️⃣ 发现“静态看不出来”的漏洞

例如：

- 命令注入（运行时拼接）
    
- 环境变量依赖
    
- 文件路径拼接
    
- 隐藏后门行为
    
- 调试接口激活
    

2️⃣ 验证可疑 ELF 是否“真能跑”

- 是否是壳 / 混淆
    
- 是否缺库
    
- 是否存在 fork / exec 行为
    
- 是否存在异常退出 / crash
    

3️⃣ 为后续模块提供“动态证据”

比如：

- 运行日志
    
- stderr/stdout
    
- exit code
    
- syscall 行为（部分 profile 会收集）
    

---

### 三、S115 的核心实现逻辑（源码思路）

> 模块路径一般在：

```bash
modules/S115_usermode_emulator.sh
```

① 输入来源

- 来自前序模块（如 `S100`, `S110`）识别的：
    
    - 可执行 ELF
        
    - 架构信息
        
    - libc 类型（glibc / uClibc / musl）
        

② 环境构建

S115 会：

1. **选择对应 qemu-user**
    
    ```bash
    qemu-arm
    qemu-mips
    qemu-mipsel
    qemu-x86_64
    ```
    
2. **构造伪 rootfs**
    
    - firmware 解包路径
        
    - `/lib /usr/lib /etc`
        
    - 设置：
        
        ```bash
        QEMU_LD_PREFIX=<fake_root>
        ```
        
3. **必要时复制 qemu 到 rootfs**  
    （为 chroot 执行）
    

---

③ 执行策略（核心）

典型执行方式类似：

```bash
qemu-arm -L ./rootfs ./bin/httpd
```

或者：

```bash
chroot ./rootfs /usr/bin/qemu-arm ./bin/httpd
```

EMBA 会：

- **限制执行时间（timeout）**
    
- **捕获 stdout / stderr**
    
- **记录 exit code**
    
- **防止 fork bomb**
    

---

④ 安全限制（非常重要）

S115 默认做了多重防护：

- ⛔ 禁止网络访问（部分 profile）
    
- ⛔ 限制 fork / exec 次数
    
- ⛔ 不允许 ptrace
    
- ⛔ 使用低权限用户
    
- ⛔ 强制 kill 超时进程
    

这也是为什么它**默认依赖 Docker / 隔离环境**

---

### 四、输出结果

S115 的输出主要体现在：

📁 日志目录

```bash
log/S115_usermode_emulator/
├── executed_binaries.txt
├── failed_binaries.txt
├── stdout_*.log
├── stderr_*.log
└── summary.log
```

📊 报告中体现

- 哪些 ELF **成功执行**
    
- 哪些 **崩溃 / 超时**
    
- 是否发现：
    
    - shell 调用
        
    - 可疑参数处理
        
    - 隐藏服务启动
        

---

### 五、它和 Docker / 系统仿真的关系

**重要结论：**

> 🔹 **S115 ≠ 全系统仿真**  
> 🔹 **S115 只做用户态 ELF 仿真**

但在 EMBA 中：

- **默认仍在 Docker 内执行**
    
- 目的是：
    
    - 防止恶意 ELF 影响宿主机
        
    - 保证依赖环境一致
        

---

### 六、常见问题 & 限制

❌ 运行失败的常见原因

|原因|说明|
|---|---|
|缺 libc|固件裁剪过度|
|架构误判|MIPS / MIPSel 混淆|
|依赖内核特性|user-mode 不支持|
|使用 ioctl / netlink|QEMU 不完整支持|

---

⚠️ 安全提醒（非常重要）

> **千万不要在裸机上手动执行 S115 模块**

即使是 user-mode：

- 仍可能执行：
    
    - rm -rf /
        
    - fork bomb
        
    - crypto miner
        
    - exploit 本地漏洞
        

---

### 七、一句话总结

> **S115_usermode_emulator 是 EMBA 中“最接近真实运行行为”的模块之一，用 QEMU 用户态仿真运行固件 ELF，为静态分析提供动态证据，但代价是复杂、慢、风险高。**

---