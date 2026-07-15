# 🔓 Lenovo TB330FU (MTK 4.19.191) Root Exploit Kit

> **设备**: Lenovo Tab (TB330FU) — MediaTek MTK 4.19.191
> **Android**: 13
> **生成**: 2026-07-10
> **源码**: https://github.com/NebuSec/CyberMeowfia

---

## 1️⃣ 设备信息

| 项目 | 值 |
|------|------|
| 型号 | **Lenovo TB330FU** |
| SoC | MediaTek (MTK) |
| 内核 | **4.19.191** (`4.19.191-g7f6d5959caf2`) |
| Android | 13 (可升级) |
| 架构 | ARM64 aarch64 |
| VA_BITS | 39 |
| 内核基址 | `0xffffffc080000000` |
| 直接映射 | `0xffffff8000000000 ~ 0xffffff9000000000` |
| vmemmap | `0xffffffc000000000` |
| 物理偏移 | `0x80000000` |

---

## 2️⃣ 漏洞利用链

```
┌────────────────────────────────────────────┐
│ Stage 1: Futex PI 条件竞争                   │
│  FUTEX_LOCK_PI / FUTEX_WAIT_REQUEUE_PI      │
│  → 8 个子进程 × 300 轮 race                  │
│  → 在 PI chain 中制造栈溢出/篡改              │
├────────────────────────────────────────────┤
│ Stage 2: PR_SET_MM 内存布局篡改              │
│  memfd_create + fallocate → 共享内存          │
│  PR_SET_MM_MAP 替换进程内存映射               │
│  → 在目标位置布置伪造数据                     │
├────────────────────────────────────────────┤
│ Stage 3: Pipe Buffer 物理内存读写             │
│  → 覆盖 pipe_buffer.page 指针                │
│  → 通过 vmemmap 定位 struct page             │
│  → 任意物理地址 → 改写 cred                  │
├────────────────────────────────────────────┤
│ Stage 4: 提权                                │
│  cred.uid = 0 / cred.caps = ~0              │
│  SELinux sid → kernel init sid               │
│  → 安装 su → root shell                      │
└────────────────────────────────────────────┘
```

---

## 3️⃣ 关键内存布局 (ARM64 VA_BITS=39)

```
用户空间:   0x0000000000000000 ~ 0x0000007fffffffff
内核空间:   0xffffff8000000000 ~ 0xffffffffffffffff
  ├─ 直接映射:   0xffffff8000000000 ~ 0xffffff9000000000
  ├─ 模块区域:   0xffffff8000000000 ~ 0xffffff8008000000
  ├─ vmalloc:    0xffffff8008000000 ~ ...
  ├─ vmemmap:    0xffffffc000000000 ~ ...  (struct page 数组)
  ├─ PCI I/O:    ...
  └─ fixmap:     ...
```

### Page 结构体

```
struct page (ARM64, 4.19):
  大小: 0x40 (64 bytes)
  compound_head: offset 0x08
  slab_cache:    offset 0x08 (非 compound 时)
  type:          offset 0x30

vmemmap 中每个物理页对应一个 struct page:
  page_vaddr = vmemmap_start + (pfn << PAGE_SHIFT) * sizeof(struct page)
             = vmemmap_start + pfn * 0x40
```

---

## 4️⃣ 结构体偏移

### struct cred (4.19 ARM64, CONFIG_KEYS=y, UID16=y)

```
offset 0:   usage          (atomic_t, 4B)
offset 4:   uid            (kuid_t, 4B)
offset 8:   gid            (kgid_t, 4B)
offset 12:  suid           (kuid_t, 4B)
offset 16:  sgid           (kgid_t, 4B)
offset 20:  euid           (kuid_t, 4B)
offset 24:  egid           (kgid_t, 4B)
offset 28:  fsuid          (kuid_t, 4B)
offset 32:  fsgid          (kgid_t, 4B)
offset 36:  securebits     (unsigned int, 4B)
offset 40:  cap_inheritable (kernel_cap_t, 8B)
offset 48:  cap_permitted   (kernel_cap_t, 8B)
offset 56:  cap_effective   (kernel_cap_t, 8B)
offset 64:  cap_bset        (kernel_cap_t, 8B)
offset 72:  cap_ambient     (kernel_cap_t, 8B)
offset 80:  jit_keyring    (u8, 1B + 7 padding)
offset 88:  session_keyring (struct key*, 8B)
offset 96:  process_keyring (struct key*, 8B)
offset 104: thread_keyring  (struct key*, 8B)
offset 112: request_key_auth (struct key*, 8B)
offset 120: security       (void*, 8B)   ← SELinux blob
offset 128: user           (struct user_struct*, 8B)
```

### SELinux task_security_struct

```
offset 0:  osid  (u32)
offset 4:  sid   (u32)
```

### struct task_struct (4.19, THREAD_INFO_IN_TASK=y)

```
offset 0x000:  thread_info (48B)
  ├─ 0x00: flags
  ├─ 0x04: status
  ├─ 0x08: cpu
  ├─ 0x0c: addr_limit
  ├─ 0x10: preempt_count
  └─ 0x18: syscallno
offset ~0x550: tasks (list_head)
offset ~0x618: pid
offset ~0x61c: tgid
offset ~0x628: real_parent
offset ~0x8e8: seccomp
  ├─ 0x00: mode
  ├─ 0x04: filter_count
  └─ 0x08: filter
```

### mm_struct

```
大小: 0x500 (1280 bytes)
slab order: 3 (32KB slab)
```

### pipe_buffer

```
每个 pipe_buffer 大小: 0x28 (40 bytes)
pipe 默认槽位: 16
pipe 最大槽位: 32
```

---

## 5️⃣ CyberMeowfia IonStack 目标偏移

> 源码: `CVE-2026-43499/exploit/src/targets/barley_prc-4.19/target.h`

注意: **该 target.h 中的 ASHMEM 等符号偏移均为 0**（需通过 runtime kernelsnitch 动态检测），目前只有内存布局基址和结构体偏移已定义。

### 已定义的基址

```c
#define KIMAGE_TEXT_BASE     0xffffffc080000000ULL
#define P0_PAGE_OFFSET       0xffffff8000000000ULL
#define P0_PHYS_OFFSET       0x80000000ULL
#define VMEMMAP_START        0xffffffc000000000ULL
```

### 需要从 vmlinux 提取的符号

| 符号 | 用途 |
|------|------|
| `init_task` | 定位 init 进程 cred |
| `selinux_enforcing` | 关闭 SELinux enforcing |
| `ashmem_fops` | 识别 ashmem 文件操作结构体 |
| `kmalloc_caches` | slab 分配器操作 |
| `anon_pipe_buf_ops` | pipe buffer 操作函数表 |
| `security_hook_heads` | LSM 钩子表 |
| `nfulnl_logger` | KASLR 滑动探测 |
| `random_boot_id_data` | KASLR 滑动探测 |
| `sysctl_bootid` | KASLR 滑动探测 |

---

## 6️⃣ 文件清单

```
lenovo-pkg/
├── README.md                    ← 本说明文件
│
├── bin/                         ← 编译好的二进制
│   ├── mtk_exploit              ← 主漏洞利用 (11KB, PIE)
│   ├── run_exploit              ← 完整漏洞利用链 (132KB, PIE)
│   ├── poc_original             ← 原始 PoC (17KB, PIE)
│   ├── kprobe                   ← 内核探测工具 (3.8KB)
│   ├── test_ashmem              ← ashmem 测试
│   ├── test_futex               ← futex 测试
│   ├── test_openat              ← openat 测试
│   ├── test_min                 ← 最小可执行测试
│   ├── hello                    ← 交叉编译验证
│   ├── fops.o                   ← 内核 fops 操作
│   ├── main.o                   ← exploit 主入口
│   ├── pipe.o                   ← pipe 利用模块
│   ├── preload.o                ← LD_PRELOAD loader
│   ├── root.o                   ← root 提权模块
│   ├── slide.o                  ← KASLR 滑动处理
│   └── util.o                   ← 通用工具
│
├── src/                         ← C 源码
│   ├── mtk_exploit.c            ← Futex PI Race + Pipe PhysRW (204行)
│   ├── mtk_offsets.h            ← 内核偏移头文件 (4KB)
│   ├── run_exploit.c            ← exploit 主入口 stub
│   ├── kfinder.c                ← 内核基址探测器
│   ├── kprobe.c                 ← 内核探针
│   └── test_*.c                 ← 各种测试源码
│
├── target/
│   └── target.h                 ← CyberMeowfia barley_prc-4.19 目标偏移
│
└── boot/
    ├── 1-Boot-NoEmul.img        ← boot 分区 (4KB, 可能是分区表)
    └── 2-Boot-NoEmul.img        ← boot 分区 (1.7MB)
```

关联的外部文件（未打包，因体积过大）：

| 文件 | 大小 | 位置 |
|------|------|------|
| `vmlinux` | 25MB | `/storage/emulated/0/MT2/apks/Y/漏洞/vmlinux` |
| `vmlinux-debug` | 25MB | 同上 `vmlinux-debug` |
| `kernel.gz` | 11MB | 同上 `kernel.gz` |
| `kernel-debug.gz` | 11MB | 同上 `kernel-debug.gz` |
| `boot.img` | 32MB | 同上 `boot.img` |
| `boot-debug.img` | 32MB | 同上 `boot-debug.img` |
| `ramdisk.cpio` | 27MB | 同上 `ramdisk.cpio` |

---

## 7️⃣ Poc_original 说明

`poc_original` 是原始的 `poc.c` 编译产物（NDK r29, not stripped），基于 socket + setsockopt 的本地 kernel 触发辅助程序，用于在本地触发内核条件竞争环境。

包含的符号（`nm -D` 可见）:
- `stamp_socket`, `stamp_pselect`, `stamp_tcp`, `stamp_process_vm`
- `stamp_keyctl`, `stamp_fd`, `stamp_futex`, `stamp_lanes`
- `waiter`, `owner`, `consumer` 线程模式
- futex PI 操作: `futex_pi_lock`, `futex_wait_requeue_pi`, `futex_cmp_requeue_pi`

---

## 8️⃣ 编译方式

```bash
# MTK Exploit（需 NDK r29+）
aarch64-linux-android-clang -O2 -pie -fPIE \
  -o mtk_exploit mtk_exploit.c -lpthread

# CyberMeowfia 完整 exploit（需 NDK r29）
cd CyberMeowfia/IonStack/CVE-2026-43499/exploit
make PROJECT=barley_prc-4.19
# 产物: build/barley_prc-4.19/bin/preload.so
```

---

## 9️⃣ 从 vmlinux 提取偏移

```bash
# 查看内核版本
strings vmlinux | grep "Linux version"

# 查找 init_task
nm vmlinux | grep init_task

# 查找 ashmem 相关符号
nm vmlinux | grep -E "ashmem|configfs|pipe"

# 查找 KASLR 滑动符号
nm vmlinux | grep -E "nfulnl_logger|boot_id|sysctl_bootid"
```

---

## ⚠️ 警告

- 本 exploit 会修改系统分区
- 可能造成设备崩溃、重启、数据丢失
- **仅在你拥有的设备上运行**
- 需要先解锁 bootloader
- 推荐在有完整系统备份的前提下运行
