# Rootme

Android 设备 Firefox 浏览器漏洞利用页面集合。利用 [CVE-2026-23274](https://github.com/NebuSec/CyberMeowfia) (Firefox JIT Type Confusion) 获取 shell，再针对特定设备执行内核提权。

> ⚠️ **免责声明**：本项目仅用于学习和研究。只能在您拥有的设备上运行，且应提前备份。
> 利用过程中设备可能崩溃、重启、数据丢失。作者不对任何滥用造成的后果负责。

## 在线访问

部署后的站点：[rootme.wssllhdg.dpdns.org](https://rootme.wssllhdg.dpdns.org/)

## 支持的设备

| 设备 | SoC | 内核 | 入口 |
|------|-----|------|------|
| **OnePlus PLQ110** (Ace 5 Pro / K3 regional) | Qualcomm Snapdragon 8 Elite | Linux 6.6.89 GKI | [CVE-2026-23274/OnePlus PLQ110/exploit.html](CVE-2026-23274/OnePlus%20PLQ110/exploit.html) |
| **Lenovo Tab TB330FU** | MediaTek | Linux 4.19.191 | [CVE-2026-23274/Lenovo Tab TB330FU/exploit.html](CVE-2026-23274/Lenovo%20Tab%20TB330FU/exploit.html) |
| 其他设备（实验） | 任意 ARM64 | 任意 | [CVE-2026-23274/index.html](CVE-2026-23274/index.html) — 走 generic 路径 |

## 利用链概览

```
Stage 1  Firefox JIT Type Confusion  →  AAR/AAW/ADDROF + RWX shellcode
                                      →  在 Firefox 沙箱内获取 unprivileged shell
Stage 2  Device-specific kernel exploit
         • MTK:   Futex PI Race + Pipe PhysRW via ashmem
         • QCOM:  Futex PI Race + Pipe PhysRW via dma-heap
                                      →  cred.uid = 0, SELinux → init sid
Stage 3  Install su → root shell
```

## 仓库结构

```
Rootme/
├── CNAME                                       ← GitHub Pages 自定义域名
├── LICENSE                                     ← GPL v3
├── index.html                                  ← 入口（链接到具体 CVE）
└── CVE-2026-23274/
    ├── index.html                              ← CVE 入口（设备选择）
    ├── exploit.html                            ← 通用 Firefox JIT 利用（iframe target）
    ├── ansi.js                                 ← ANSI escape 渲染器
    ├── arm                                     ← 不支持设备的 fallback preload (ELF)
    ├── Lenovo Tab TB330FU/                     ← MTK 4.19.191 kit
    │   ├── exploit.html
    │   ├── README.md
    │   ├── bin/                                ← 已编译 ARM64 二进制
    │   ├── src/                                ← C 源码
    │   ├── target/target.h                     ← CyberMeowfia IonStack 偏移
    │   └── boot/
    └── OnePlus PLQ110/                         ← QCOM 6.6 GKI kit
        ├── exploit.html
        ├── README.md
        ├── DOCKER_WORKFLOW.md                  ← 编译/vmlinux 提取工作流
        ├── bin/                                ← 已编译 ARM64 二进制（NDK r28b）
        ├── src/                                ← C 源码
        ├── target/target.h                     ← CyberMeowfia IonStack 偏移
        └── boot/                               ← PLQ110 关键镜像（xz 压缩，~16 MB）
            ├── boot.img.xz                     ← GKI boot.img
            ├── vmlinux.xz                      ← 提取的 vmlinux ELF
            ├── init_boot.img.xz                ← GKI init ramdisk
            ├── dtbo.img.xz                     ← device tree overlay
            └── vbmeta*.img                     ← AVB 链 (3 个分区)
```

## 使用前提

- **目标设备**：必须先用 `fastboot flashing unlock` 解锁 bootloader
- **客户端浏览器**：[Firefox 151.0 arm64-v8a](https://archive.mozilla.org/pub/fenix/releases/151.0/android/fenix-151.0-android-arm64-v8a/fenix-151.0.multi.android-arm64-v8a.apk)
- **网络**：设备需要能访问本页面（部署后通过 HTTPS 提供服务）

## 自行编译 / 修改

每个设备 kit 的 `bin/` 目录已附带预编译产物。若要修改源码后重新编译：

```bash
# 1. 拉取交叉编译镜像（自带 NDK r28b, clang 19.0.0）
docker pull dockcross/android-arm64

# 2. 进入仓库根目录后，参考各 kit 内的 DOCKER_WORKFLOW.md / bin/README.md
```

详见 `CVE-2026-23274/OnePlus PLQ110/DOCKER_WORKFLOW.md`。

## 相关项目

- **上游 Firefox JIT exploit**：[hexo141/Rootme](https://github.com/hexo141/Rootme)
- **CyberMeowfia IonStack**：[NebuSec/CyberMeowfia](https://github.com/NebuSec/CyberMeowfia)

## License

GPL v3 — 详见 [LICENSE](LICENSE)。
