# PLQ110 Docker 工作流 (实证)

> 2026-07-12 测试结果。回答"有没有现成 Docker 镜像可以编译 + 提取符号"这个问题。

## TL;DR

| 任务 | 是否有现成 image? | 实测结果 |
|------|---|---|
| **编译 aarch64 PIE 二进制** | ✅ `dockcross/android-arm64` (1.94 GB, NDK r28b, clang 19.0.0) | 8/8 二进制全部编译成功 |
| **从 boot.img 解出 kernel + 提取 vmlinux** | ✅ 用本目录的 `unpack_boot_pybootimg.py` + dockcross 自带 python | kernel 36.6MB 已提取；嵌入的 18.4MB 子-ELF 可提取 |
| **从 vmlinux 提取符号 (`nm`)** | ❌ GKI 内核 stripped，symtab 为空 | **必须运行时 `/proc/kallsyms`** |
| **完整的 Android exploit-dev 一体 image** | ❌ 不存在 | cloudfuzz/android-kernel-exploitation 是 build full kernel (小时级)，非 exploit dev |

## 详细命令

### 1. 拉镜像（一次性）

```powershell
docker pull dockcross/android-arm64
# 1.94 GB 下载，~2 min on cable
docker images dockcross/android-arm64
# REPOSITORY                TAG       IMAGE ID        SIZE
# dockcross/android-arm64   latest    0a6215fb81de    1.94GB
```

### 2. 编译 8 个 PLQ110 二进制

> 将下方 `$work` 改为你的本地仓库根目录（包含 `Rootme/` 的那一层）。

```powershell
# 单行命令（已验证可用）：
$work = "<path-to-repo-root>"   # e.g. "D:\code\Rootme-repo"
docker run --rm -v "${work}:/work" -w /work dockcross/android-arm64 bash -c '
SRC="/work/Rootme/CVE-2026-23274/OnePlus PLQ110/src"
BIN="/work/Rootme/CVE-2026-23274/OnePlus PLQ110/bin"
mkdir -p "$BIN"
cd "$SRC"
for pair in \
    "qcom_exploit:qcom_exploit.c" \
    "run_exploit:run_exploit.c" \
    "kprobe:kprobe.c" \
    "hello:hello.c" \
    "test_dma_heap:test_dma_heap.c" \
    "test_futex:test_futex.c" \
    "test_min:test_min.c" \
    "test_openat:test_openat.c" ; do
    name="${pair%%:*}"; src="${pair##*:}"
    $CC -O2 -pie -fPIE -I"$SRC/../target" -I"$SRC" -o "$BIN/$name" "$src" 2>/dev/null
    strip "$BIN/$name"
    echo "[+] $name -> $(stat -c%s "$BIN/$name") bytes"
done
'
```

或者直接：
```bash
bash tools/build-with-docker.sh
```

### 3. 验证产物

```powershell
Get-ChildItem "<path-to-repo-root>\Rootme\CVE-2026-23274\OnePlus PLQ110\bin"
```

实测产物大小（clang 19.0.0, -O2, stripped）：
| 文件 | 大小 | 验证 |
|------|------|------|
| `qcom_exploit` | 11,968 B | ELF 64-bit LSB PIE, ARM aarch64 |
| `run_exploit` | 6,704 B | ELF 64-bit LSB PIE, ARM aarch64 |
| `kprobe` | 7,688 B | ELF 64-bit LSB PIE, ARM aarch64 |
| `hello` | 6,032 B | ELF 64-bit LSB PIE, ARM aarch64 |
| `test_dma_heap` | 7,264 B | ELF 64-bit LSB PIE, ARM aarch64 |
| `test_futex` | 6,992 B | ELF 64-bit LSB PIE, ARM aarch64 |
| `test_min` | 5,792 B | ELF 64-bit LSB PIE, ARM aarch64 |
| `test_openat` | 6,624 B | ELF 64-bit LSB PIE, ARM aarch64 |

### 4. 从 boot.img 提取 kernel + 嵌入 vmlinux

仓库 `boot/` 已附带压缩好的 `boot.img.xz`（~10MB）和 `vmlinux.xz`（~4MB）。
解压后即可用于分析：

```bash
# 在本地解压（无需 Docker）
cd Rootme/CVE-2026-23274/OnePlus\ PLQ110/boot
xz -dk boot.img.xz
xz -dk vmlinux.xz
```

如果需要从 boot.img 重新提取嵌入的 vmlinux（验证完整性 / 测试 unpack 工具）：

```powershell
$work = "<path-to-repo-root>"
docker run --rm --entrypoint bash -v "${work}:/work" -w /work dockcross/android-arm64 `
    -lc "python3 /work/tools/unpack_boot_pybootimg.py /work/Rootme/CVE-2026-23274/'OnePlus PLQ110'/boot/boot.img /tmp/unpack"
```

实测输出：
```
[*] boot image size: 100,663,296 bytes
[*] header_version  = 4
[*] kernel_size     = 36,661,760
[+] wrote .../kernel (36,661,760 bytes)

[*] === kernel format ===
  arm64 Image header detected (offset 0x0)  <- 这是 GKI 标准格式
  -> kernel section is raw arm64 Image

[*] === Linux version string ===
  Linux version 6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k ...

[*] === ELF (vmlinux embedded?) ===
  ELF magic at 0x1099000 - vmlinux is embedded
[+] wrote .../vmlinux (19,257,856 bytes)
```

### 5. 符号提取 — **结果：必须运行时**

PLQ110 vmlinux 是 **stripped GKI production kernel**：

```
$ file vmlinux
... ELF 64-bit LSB shared object, ARM aarch64, ... stripped

$ readelf -s vmlinux
Symbol table '.dynsym' contains 5 entries  <-- 仅 5 个动态符号

$ nm vmlinux
(no symbols)  <-- symtab 为空
```

**EXPORT_SYMBOL 池可见的符号**（验证：它们在内核里，只是地址不在静态 symtab）：

| 符号 | 在 strings 池里? |
|------|---|
| `init_task` | ✅ |
| `kmalloc_caches` | ✅ |
| `security_hook_heads` | ✅ |
| `root_task_group` | ✅ |
| `lsm_blob_sizes` | ✅ |
| `init_cred` | ❌ static |
| `selinux_enforcing` | ❌ static |
| `anon_pipe_buf_ops` | ❌ static |
| `nfulnl_logger` | ❌ static |
| `dma_heap_*` ops | ❌ static |

**kallsyms 内部表** (`kallsyms_token_table` / `kallsyms_num_syms` / ...) 在二进制里**也找不到 ASCII 名称** — 它们用 token 压缩编码（6.6 内核默认）。

**结论**：和 Lenovo kit 完全一致 — `target.h` 中所有需要 vmlinux 提取的偏移**只能通过运行时**获取：
- 浏览器 JIT exploit 成功 → shell
- shell + 内核 exploit primitive → 读 `/proc/kallsyms` 拿到符号地址
- 减去 `KIMAGE_TEXT_BASE` 得到 `_OFF` 写回 target.h
- 这就是 README §5 / §6 里 "kernelsnitch" 的作用

## 关于"一体化 image"

调查过的"看起来对路"的镜像：

| Image | 用途 | 是否适用 |
|---|---|---|
| `dockcross/android-arm64` | aarch64 cross-compile | ✅ **首选** (NDK r28b 自带) |
| `dockcross/android-arm64-api24` | 同上, API 24 | (同 dockcross/android-arm64) |
| `llama-android-builder` (本地缓存) | Gradle/Java Android app | ❌ 无 NDK |
| `cimg/android:ndk` | CircleCI 完整 SDK + NDK | ✅ 但更大 (~5GB) |
| `cloudfuzz/android-kernel-exploitation` | 漏洞研究 workshop | ❌ build full kernel (~小时级，100GB) |
| `locus-x64/android-kernel-exploitation-lab` | 同上变体 | ❌ 同上 |

**没有专门的"Android 内核 exploit dev"prebuilt image。** 社区都用 dockcross + 自己叠加 mkbootimg/pahole。

## 想要 mkbootimg / pahole 怎么办

dockcross 没有这两个。两个方案：

### A) 一次性安装（容器内网络通畅时）

```bash
docker run --rm -it dockcross/android-arm64 bash
apt-get update && apt-get install -y mkbootimg dwarves
```

### B) 在本仓库 Dockerfile.exploit-dev 之上构建

我们之前写的 `Dockerfile.exploit-dev` (based on `llama-android-builder`) 把 NDK r27c + mkbootimg + pahole + binutils 全打包，更适合完整 exploit dev workflow。但 base 镜像不如 dockcross 干净。

推荐：
- **只用 dockcross** 做编译 + Python 工具脚本（用本仓库的 `tools/unpack_boot_pybootimg.py`）
- 若需要 pahole/nm 高级分析，叠加 `Dockerfile.exploit-dev`
