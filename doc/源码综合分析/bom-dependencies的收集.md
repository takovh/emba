`dependencies` 不是从一个独立的“依赖数据库”统一拉取的；它首先由各个 **SBOM 采集子模块从固件中的包/锁文件/二进制元数据解析出来**，然后由 `S08_main_package_sbom.sh` 统一关联成 CycloneDX 的依赖图。

### 1. 原始依赖数据：各解析器从固件内容中收集

主要位置是：

```text
modules/S08_main_package_sbom_modules/
```

各子模块把解析到的依赖写成组件 JSON 的 `properties` 项，格式为：

```text
dependency:<依赖名或版本约束>
```

例如：

- Debian 包数据库：  
  `S08_submodule_debian_pkg_mgmt_parser.sh`  
  从固件内的 `dpkg/status` 中逐包读取包元数据（包括 `Depends` 等字段），并将依赖加入：
  ```bash
  lPROP_ARRAY_INIT_ARR+=( "dependency:${lAPP_DEP#\ }" )
  ```
  见约第 176–179 行。

- Node.js：  
  `S08_submodule_nodejs_pcklockparser.sh`  
  从 `package-lock.json` 中读取 `.dependencies`，转为 `dependency:` 属性。约第 136–155 行。

- 同一机制也用于：
  - RPM：`S08_submodule_rpm_*`
  - OpenWrt/opkg/IPK：`S08_submodule_openwrt_*`
  - APK、BSD 包、Composer、Cargo 等。

这些属性最终经下面的公共函数序列化为组件 JSON：

```text
helpers/helpers_emba_sbom_helpers.sh
└── build_sbom_json_properties_arr()
```

它把 `dependency:xxx` 变为 JSON 中名称以 `:dependency` 结尾的 property。

---

### 2. 二进制级依赖：`S09` 从动态链接信息收集

除了包管理器元数据，二进制识别模块也会补充 ELF 的动态库依赖：

```text
modules/S09_firmware_base_version_check.sh
```

对 `dynamically linked` 的 ELF，代码运行：

```bash
ldd "${lBINARY_PATH}"
```

取输出的第一个字段，并逐项写入：

```bash
lPROP_ARRAY_INIT_ARR+=( "dependency:${lBIN_DEPENDENCY}" )
```

位置约为 `S09_firmware_base_version_check.sh:568-578`。

因此此处的依赖来源是 ELF 的动态链接器/`DT_NEEDED` 可解析信息，而非包管理器数据库。

---

### 3. 依赖关系图：`S08_main_package_sbom.sh` 将名称映射为 `bom-ref`

实际构建组件之间的关系发生在：

```text
modules/S08_main_package_sbom.sh
└── build_dependency_tree()
    └── create_comp_dep_tree_threader()
```

流程：

1. 枚举运行时产生的组件 JSON：

   ```bash
   find "${SBOM_LOG_PATH}" -maxdepth 1 -type f -name "*.json"
   ```

2. 从每个组件的 `properties` 中提取依赖值：

   ```bash
   jq -rc '.properties[] | select(.name | endswith(":dependency")).value'
   ```

   即约 `S08_main_package_sbom.sh:137`。

3. 仅在**同一个 SBOM 来源/group**里查找名称匹配的组件，例如 Debian 包只和 `debian_pkg_mgmt_*` 类型的组件匹配：

   ```bash
   grep -l "name\":\"${lSBOM_COMP_DEP}\"" \
     "${SBOM_LOG_PATH}"/"${lSBOM_COMP_SOURCE}"_*
   ```

4. 找到目标组件后读取其 `"bom-ref"`，生成：

   ```json
   {
     "ref": "当前组件的 bom-ref",
     "dependsOn": ["依赖组件的 bom-ref"]
   }
   ```

5. 单组件关系写入：

   ```text
   ${SBOM_LOG_PATH}/SBOM_deps/SBOM_dependency_<bom-ref>.json
   ```

   同时会输出便于查看的：

   ```text
   ${SBOM_LOG_PATH}/SBOM_dependencies.txt
   ```

若依赖名称在当前固件的同源组件中找不到，EMBA 仍会保留一个带 `NO_VALID_REF` 的占位标识，而不会建立到真实组件的引用。

---

### 4. 最终 CycloneDX 输出

最后：

```text
modules/F15_cyclonedx_sbom.sh
```

读取：

```text
${SBOM_LOG_PATH}/SBOM_deps/SBOM_dependency_*.json
```

并合并到最终的：

```text
${SBOM_LOG_PATH}/EMBA_cyclonedx_sbom.json
```

其中对应 CycloneDX 顶层的 `dependencies` 数组。

**简言之：**  
依赖的“事实数据”来自固件内的包管理元数据、lock 文件及 ELF 动态链接信息；`S08_main_package_sbom.sh` 再按组件名称和同一 `group` 解析为 `bom-ref → dependsOn` 关系。