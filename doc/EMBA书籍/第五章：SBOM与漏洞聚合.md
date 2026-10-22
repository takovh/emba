
## 第五章：SBOM与漏洞聚合


_EMBA_ 的主要目标始终是通过分析固件镜像，准确地了解威胁的真实情况。几年前目标受众仅为渗透测试员，但在当今 _EMBA_ 领域，软件开发者、产品负责人和产品安全团队也在利用她实现不同的目标。

随着时间推移，_EMBA_ 不断成长，如今她不再只是一个固件分析器。如今，_EMBA_ 被用来检测每一个未知二进制的细节。虽然我们主要关注的是分析基于Linux的固件，但我们也发现 _EMBA_ 也被用于[UEFI](https://github.com/e-m-b-a/emba/wiki/UEFI-analysis)、Windows二进制文件、Linux二进制文件、脚本、Android APK以及许多其他东西。除了被测试目标高度分散外，我们还看到对SBOM产生的需求在增长。_EMBA_ 长期以来包含[某种基础的 SBOM 支持](https://github.com/e-m-b-a/emba/wiki/Aggregator)，但由于我们分析的大多数固件镜像并不依赖包管理器，因此直到今天才看到对广泛支持它们的需求。

现在，我们调整了方法，支持各种包管理器、包类型以及更多来源，以从每个测试候选中获得准确的SBOM。

**支持的来源**

[https://github.com/e-m-b-a/emba/wiki/SBOM-environment#supported-sources](https://github.com/e-m-b-a/emba/wiki/SBOM-environment#supported-sources)

除了作为SBOM源的二进制分析机制外，_EMBA_ 现在能够从以下来源提取详细信息：
- ✅Binaries and libraries (S09 - excluded from sbom-minimal profile)
- ✅Linux Kernel (S24)
- ✅Linux Kernel+modules (s25)
- ✅Linux distribution identification (s06)
- ✅RPM package management system (S08)
- ✅RPM packages (S08)
- ✅Debian package management system (S08)
- ✅Debian deb Package support (S08)
- ✅OpenWRT Package management system (S08)
- ✅OpenWRT ipk Package support (S08)
- ✅Python PIP package management system (S08)
- ✅Python requirements files (S08)
- ✅Python Pipfile.lock (S08)
- ✅Python poetry (S08)
- ✅Python wheel (S08)
- ✅FreeBSD pkg packages (S08)
- ✅Java archives (jar, war - S08)
- ✅Alpine APK package support (S08)
- ✅Rust cargo.lock (S08)
- ✅Ruby gem (S08)
- ✅JavaScript - npm (S08)
- ✅Windows binary exif data (S08)
- ✅Windows binary extraction and analysis (S08)
- ✅C/C++ package manager - conanfile (S08)
- ✅PHP composer (S08)
- ✅Perl CPAN (S08)