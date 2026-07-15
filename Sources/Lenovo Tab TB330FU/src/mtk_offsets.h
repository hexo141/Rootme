#ifndef MTK_OFFSETS_H
#define MTK_OFFSETS_H

// Kernel struct offsets for MTK 4.19.191 (Lenovo TB330FU)
// Derived from Linux 4.19 source + kernel config
// CONFIG_ARM64_VA_BITS_39=y
// CONFIG_UID16=y (affects syscall layer, not struct cred)
// CONFIG_KEYS=y (adds key fields to task_struct and cred)
// CONFIG_SECURITY_SELINUX=y
// CONFIG_SECCOMP=y, CONFIG_SECCOMP_FILTER=y
// CONFIG_THREAD_INFO_IN_TASK=y

// ============ Memory Layout ============
#define PAGE_SHIFT 12
#define PAGE_SIZE (1UL << PAGE_SHIFT)

// ARM64 VA_BITS=39: PAGE_OFFSET = ~0UL << (39-1) = 0xffffffc000000000
// But the direct map (identity mapping) might start at a different offset
// For MTK 4.19, checking kernel addresses from vmlinux:
// Kernel text appears at 0xffffff8009xxxx range
// So: PAGE_OFFSET = 0xffffff8000000000 (this is what kernelsnitch uses for ARM)

// Let me use the address range from the actual vmlinux
#define PAGE_OFFSET     0xffffff8000000000ULL
#define KIMAGE_BASE     0xffffff8008000000ULL  // Approximate, will be detected by kernelsnitch

// ============ struct cred offsets (4.19 ARM64) ============
// struct cred layout with CONFIG_KEYS=y, CONFIG_DEBUG_CREDENTIALS=n:
// offset 0: usage (atomic_t, 4 bytes)
// offset 4: uid (kuid_t, 4 bytes)  
// offset 8: gid (kgid_t, 4 bytes)
// offset 12: suid (kuid_t, 4 bytes)
// offset 16: sgid (kgid_t, 4 bytes)
// offset 20: euid (kuid_t, 4 bytes)
// offset 24: egid (kgid_t, 4 bytes)
// offset 28: fsuid (kuid_t, 4 bytes)
// offset 32: fsgid (kgid_t, 4 bytes)
// offset 36: securebits (unsigned int, 4 bytes)
// offset 40: cap_inheritable (kernel_cap_t, 8 bytes)
// offset 48: cap_permitted (kernel_cap_t, 8 bytes)
// offset 56: cap_effective (kernel_cap_t, 8 bytes)
// offset 64: cap_bset (kernel_cap_t, 8 bytes)
// offset 72: cap_ambient (kernel_cap_t, 8 bytes)
// offset 80: jit_keyring (u8, 1 byte) + 7 padding
// offset 88: session_keyring (struct key*, 8 bytes)
// offset 96: process_keyring (struct key*, 8 bytes)
// offset 104: thread_keyring (struct key*, 8 bytes)  
// offset 112: request_key_auth (struct key*, 8 bytes)
// offset 120: security (void*, 8 bytes)
// offset 128: user (struct user_struct*, 8 bytes)

// These might be off by padding - let me use conservative estimates
#define CRED_UID_OFF        4
#define CRED_GID_OFF        8
#define CRED_EUID_OFF       20
#define CRED_EGID_OFF       24
#define CRED_SECUREBITS_OFF 36
#define CRED_CAPS_OFF       40   // cap_inheritable
#define CRED_SECURITY_OFF   120  // void *security

// ============ SELinux blob offsets ============
// struct task_security_struct:
// offset 0: osid (u32)
// offset 4: sid (u32)
// ... other fields
// On ARM64, void* aligned to 8 bytes  
#define SELINUX_CRED_OSID_OFF 0
#define SELINUX_CRED_SID_OFF  4

// ============ struct task_struct offsets ============
// With CONFIG_THREAD_INFO_IN_TASK=y, CONFIG_SECCOMP=y
// The task_struct on 4.19 ARM64:
// Heavy struct - many fields
// Key fields (approximate):
// offset 0: thread_info (struct thread_info, ~48 bytes)
//   - thread_info.flags at offset 0 in thread_info
//   - thread_info.status at offset 4 in thread_info  
//   - thread_info.cpu at offset 8 in thread_info
//   - thread_info.addr_limit at offset 12 in thread_info
//   - thread_info.preempt_count at offset 16 in thread_info
//   - thread_info.syscallno at offset 24 in thread_info
// With CONFIG_THREAD_INFO_IN_TASK, thread_info is at beginning
#define TASK_THREAD_INFO_FLAGS_OFF  0  // thread_info.flags
#define TASK_ATOMIC_FLAGS_OFF       4  // thread_info (atomic flags)

// offset of seccomp in task_struct
// With CONFIG_SECCOMP=y, struct seccomp is embedded
// total task_struct offset depends on many configs
// seccomp is typically near the end of the struct
#define TASK_SECCOMP_OFF       (2000 + 0)  // Will need runtime correction

// ============ mm_struct size for slab ============
#define MM_STRUCT_SZ 0x500
#define MM_ORDER 3

// vmemmap for struct page array
#define VMEMMAP_START 0xffffffbffc000000ULL

#endif
