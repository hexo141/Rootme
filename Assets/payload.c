/*
 * payload.c — KernelSU 自动越狱（late-load）payload
 *
 * 作用：等价于在 KernelSU Manager 主界面点击"越狱"按钮，但无需用户手动操作。
 *       运行 ./payload 成功后，再次打开 KernelSU Manager 即显示已越狱（jailbreak 模式）。
 *
 * 工作策略（按优先级自动选择，兼容不同 KernelSU 版本）：
 *   策略 A（推荐）：定位已安装的 ksud 二进制，调用 `ksud late-load`
 *                  —— ksud 自带从 rust-embed 内存提取匹配 KMI 的 .ko 并完成
 *                     全部越狱流程，自动适配所有 KernelSU 版本
 *   策略 B（fallback）：用户提供 .ko 路径，payload 自行做 ELF 重定位 + init_module
 *
 * ksud 定位顺序：
 *   1. /data/adb/ksu/bin/ksud           （KernelSU 已安装但未加载 ko 时）
 *   2. /data/adb/ksud                    （DAEMON_PATH）
 *   3. 从已安装 KernelSU Manager APK 的 lib/arm64-v8a/libksud.so 提取
 *      - 搜索 /data/app/.../me.weishu.kernelsu-.../lib/arm64/libksud.so
 *      - 搜索 /data/app/.../io.github.rifsxd.kernelsu-.../lib/arm64/libksud.so
 *      - 兼容 Android 11+ 的隔离存储: /data/user_de/0/<pkg>/
 *   4. 用户通过 -p 显式指定 ksud 路径
 *
 * 运行要求（与 Manager 越狱按钮相同的前提）：
 *   - SELinux 处于 Permissive 宽容模式（late-load 需 insmod）
 *   - 进程具备足够权限（root，或来自 app_zygote 等特权上下文）
 *   - 设备已安装 KernelSU Manager（提供 ksud + 匹配的 .ko）
 *
 * 用法：
 *   ./payload                      # 自动定位 ksud 并执行 late-load
 *   ./payload -p /path/to/ksud     # 显式指定 ksud 路径
 *   ./payload -k android13-5.10    # 手动指定 KMI
 *   ./payload -s                   # 传入 allow_shell=1
 *   ./payload -d /path/to/.ko      # 直接 insmod 模式（策略 B，跳过 ksud）
 *
 * 编译（NDK aarch64）：
 *   $NDK/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android24-clang \
 *       -O2 -o payload payload.c
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/utsname.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <sys/sendfile.h>
#include <elf.h>
#include <limits.h>
#include <dirent.h>

/* ---------- 调试输出宏 ---------- */
#define LOGI(fmt, ...) fprintf(stderr, "[payload] " fmt "\n", ##__VA_ARGS__)
#define LOGE(fmt, ...) fprintf(stderr, "[payload] ERROR: " fmt "\n", ##__VA_ARGS__)
#define LOGW(fmt, ...) fprintf(stderr, "[payload] WARN: " fmt "\n", ##__VA_ARGS__)

/* ---------- KernelSU UAPI 常量（与 supercall.h 一致） ---------- */
#define KSU_INSTALL_MAGIC1 0xDEADBEEFu
#define KSU_INSTALL_MAGIC2 0xCAFEBABEu
#define KSU_IOCTL_GET_INFO        0x80104b02u  /* _IOR('K', 2, struct ksu_get_info_cmd) */
#define KSU_IOCTL_GET_INFO_LEGACY 0x80004b02u  /* _IOC(_IOC_READ, 'K', 2, 0) */
#define KSU_PRCTL_MAGIC 0xDEADBEEF
#define KSU_CMD_GET_VERSION 2

/* ---------- 已知 KernelSU Manager 包名（不同版本/fork） ---------- */
static const char *KSU_PACKAGES[] = {
    "me.weishu.kernelsu",        /* 官方 */
    "me.weishu.kernelsu.pr",     /* 官方 PR 构建 */
    "io.github.rifsxd.kernelsu", /* 常见 fork */
    "io.github.weishu.kernelsu", /* 其他 fork */
    NULL,
};

/* ---------- 文件工具 ---------- */
static uint8_t *read_whole_file(const char *path, size_t *out_len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    struct stat st;
    if (fstat(fd, &st) < 0) { close(fd); return NULL; }
    size_t len = (size_t)st.st_size;
    uint8_t *buf = malloc(len + 1);
    if (!buf) { close(fd); return NULL; }
    size_t off = 0;
    while (off < len) {
        ssize_t n = read(fd, buf + off, len - off);
        if (n < 0) { if (errno == EINTR) continue; free(buf); close(fd); return NULL; }
        if (n == 0) break;
        off += (size_t)n;
    }
    close(fd);
    *out_len = off;
    return buf;
}

static int write_file(const char *path, const char *data)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) return -1;
    ssize_t n = write(fd, data, strlen(data));
    close(fd);
    return n < 0 ? -1 : 0;
}

static int file_exists(const char *path)
{
    struct stat st;
    return stat(path, &st) == 0;
}

static int copy_file(const char *src, const char *dst)
{
    int in = open(src, O_RDONLY);
    if (in < 0) return -1;
    int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, 0755);
    if (out < 0) { close(in); return -1; }
    struct stat st;
    fstat(in, &st);
    ssize_t n = sendfile(out, in, NULL, st.st_size);
    close(in);
    close(out);
    return n == st.st_size ? 0 : -1;
}

/* ---------- SELinux 状态 ---------- */
static const char *get_selinux_status(void)
{
    int fd = open("/sys/fs/selinux/enforce", O_RDONLY);
    if (fd < 0) {
        if (errno == ENOENT) return "Disabled";
        return "Unknown";
    }
    char val[8] = {0};
    ssize_t n = read(fd, val, sizeof(val) - 1);
    close(fd);
    if (n <= 0) return "Unknown";
    return val[0] == '1' ? "Enforcing" : "Permissive";
}

/* ---------- KernelSU 是否已加载 ---------- */
static int has_kernelsu_v2(void)
{
    int fd = -1;
    syscall(SYS_reboot, (long)KSU_INSTALL_MAGIC1, (long)KSU_INSTALL_MAGIC2, 0L, &fd);
    if (fd < 0) return 0;
    struct { uint32_t version, flags, features, uapi_version; } cmd = {0};
    uint32_t version = 0;
    if (ioctl(fd, KSU_IOCTL_GET_INFO, &cmd) == 0) version = cmd.version;
    else {
        struct { uint32_t version, flags, features; } legacy = {0};
        if (ioctl(fd, KSU_IOCTL_GET_INFO_LEGACY, &legacy) == 0) version = legacy.version;
    }
    close(fd);
    return version != 0;
}

static int has_kernelsu_legacy(void)
{
    uint32_t version = 0;
    syscall(SYS_prctl, KSU_PRCTL_MAGIC, KSU_CMD_GET_VERSION, &version);
    return version != 0;
}

static int has_kernelsu(void)
{
    return has_kernelsu_v2() || has_kernelsu_legacy();
}

/* ---------- KMI 检测（与 boot_patch.rs::parse_kmi 一致） ---------- */
static int detect_kmi(char *out, size_t out_sz)
{
    struct utsname uts;
    if (uname(&uts) != 0) return -1;
    char kver[16] = {0}, aver[16] = {0};
    const char *s = uts.release;
    /* 解析内核主.次版本 */
    for (const char *p = s; *p; p++) {
        if (p[0] >= '0' && p[0] <= '9' && p[1] == '.' && p[2] >= '0' && p[2] <= '9') {
            if (p == s || !(p[-1] >= '0' && p[-1] <= '9')) {
                size_t i = 0;
                while (*p && (*p == '.' || (*p >= '0' && *p <= '9')) && i < sizeof(kver) - 1)
                    kver[i++] = *p++;
                kver[i] = 0;
                char *dot = strchr(kver, '.');
                if (dot) { char *next = dot + 1; while (*next && *next >= '0' && *next <= '9') next++; *next = 0; }
                break;
            }
        }
    }
    /* 解析 androidN */
    const char *ap = strstr(s, "android");
    if (ap) {
        size_t i = 0;
        while (*ap && ((*ap >= 'a' && *ap <= 'z') || (*ap >= '0' && *ap <= '9')) && i < sizeof(aver) - 1)
            aver[i++] = *ap++;
        aver[i] = 0;
    }
    if (kver[0] == 0 || aver[0] == 0) return -1;
    snprintf(out, out_sz, "%s-%s", aver, kver);
    return 0;
}

/* ========================================================================
 * 策略 A：定位 ksud 并调用 `ksud late-load`
 * ==================================================================== */

/* 在 /data/app 下搜索某包名对应的 base.apk 同级 lib/arm64/libksud.so
 * Android 包安装路径格式：
 *   /data/app/<random>~/<package_name>-<random>/lib/arm64/libksud.so   (旧)
 *   /data/app/~~<random>==/<package_name>-<random>/lib/arm64/libksud.so (A11+)
 */
static int find_ksud_in_data_app(const char *pkg, char *out, size_t out_sz)
{
    DIR *top = opendir("/data/app");
    if (!top) return -1;
    struct dirent *e;
    char pkg_prefix[128];
    /* 路径中包名可能带 -<random> 后缀，用前缀匹配 */
    snprintf(pkg_prefix, sizeof(pkg_prefix), "%s-", pkg);
    int found = 0;
    while ((e = readdir(top)) != NULL) {
        if (e->d_name[0] == '.') continue;
        /* 一级目录形如 ~~xxx== 或 <pkg>-xxx */
        char dir1[PATH_MAX];
        snprintf(dir1, sizeof(dir1), "/data/app/%s", e->d_name);
        DIR *d2 = opendir(dir1);
        if (!d2) continue;
        struct dirent *e2;
        while ((e2 = readdir(d2)) != NULL) {
            if (strncmp(e2->d_name, pkg_prefix, strlen(pkg_prefix)) != 0) continue;
            /* 尝试 lib/arm64/libksud.so（A11+ 隔离存储可能用 lib/arm64-v8a） */
            const char *abis[] = {"lib/arm64", "lib/arm64-v8a"};
            for (size_t i = 0; i < sizeof(abis) / sizeof(abis[0]); i++) {
                snprintf(out, out_sz, "%s/%s/%s/libksud.so", dir1, e2->d_name, abis[i]);
                if (file_exists(out)) { found = 1; break; }
            }
            if (found) break;
        }
        closedir(d2);
        if (found) break;
    }
    closedir(top);
    return found ? 0 : -1;
}

/* 定位 ksud：返回 0 成功，-1 失败 */
static int locate_ksud(const char *explicit_path, char *out, size_t out_sz)
{
    /* 1. 用户显式指定 */
    if (explicit_path) {
        if (file_exists(explicit_path)) {
            strncpy(out, explicit_path, out_sz - 1);
            return 0;
        }
        LOGE("指定的 ksud 不存在: %s", explicit_path);
        return -1;
    }
    /* 2. KernelSU 已安装路径 */
    const char *common_paths[] = {
        "/data/adb/ksu/bin/ksud",  /* BINARY_DIR/ksud */
        "/data/adb/ksud",           /* DAEMON_PATH */
        "/data/adb/ksu/bin/ksud_real",
        "/system/bin/ksud",         /* 极少情况下预置 */
        NULL,
    };
    for (int i = 0; common_paths[i]; i++) {
        if (file_exists(common_paths[i])) {
            strncpy(out, common_paths[i], out_sz - 1);
            LOGI("找到 ksud（已安装）: %s", out);
            return 0;
        }
    }
    /* 3. 从已安装 KernelSU Manager APK 中提取 libksud.so */
    LOGI("ksud 未安装，尝试从已安装的 KernelSU Manager 提取 libksud.so...");
    char tmp_so[PATH_MAX];
    for (int i = 0; KSU_PACKAGES[i]; i++) {
        char so_path[PATH_MAX];
        if (find_ksud_in_data_app(KSU_PACKAGES[i], so_path, sizeof(so_path)) == 0) {
            LOGI("在包 %s 中找到 libksud.so: %s", KSU_PACKAGES[i], so_path);
            /* libksud.so 本身就是可执行 ELF（ksud 编译为 cdylib + 可执行），
             * 直接执行即可。复制到可写位置以便设置可执行权限。 */
            snprintf(tmp_so, sizeof(tmp_so), "/data/local/tmp/.payload_ksud_%d", i);
            if (copy_file(so_path, tmp_so) == 0) {
                chmod(tmp_so, 0755);
                strncpy(out, tmp_so, out_sz - 1);
                LOGI("复制到临时路径: %s", out);
                return 0;
            }
            /* 复制失败时直接用原路径（若已有可执行权限） */
            strncpy(out, so_path, out_sz - 1);
            return 0;
        }
    }
    LOGE("未找到 ksud，可通过 -p 显式指定 ksud 路径，或用 -d 指定 .ko 直接加载");
    return -1;
}

/* 执行 ksud late-load */
static int run_ksud_late_load(const char *ksud_path, const char *kmi, int allow_shell)
{
    /* 构造参数：
     *   ksud late-load [--kmi <kmi>] [--allow-shell] --package-name <pkg>
     * 注意：package_name 影响 late_load 最后重启 Manager 的目标，可省略用默认。
     *       这里不传 --magica（非 magica 模式），直接执行 late_load::run。
     */
    pid_t pid = fork();
    if (pid < 0) { LOGE("fork: %s", strerror(errno)); return -1; }
    if (pid == 0) {
        /* 子进程：重定向 stderr 到 stdout 便于观察 */
        dup2(STDERR_FILENO, STDOUT_FILENO);

        /* argv 数组：预留足够空间 */
        char *argv[16];
        int argc = 0;
        argv[argc++] = (char *)"ksud";
        argv[argc++] = (char *)"late-load";
        if (kmi) {
            argv[argc++] = (char *)"--kmi";
            argv[argc++] = (char *)kmi;
        }
        if (allow_shell) argv[argc++] = (char *)"--allow-shell";
        argv[argc] = NULL;

        LOGI("exec: %s %s", ksud_path,
             kmi ? (allow_shell ? "--kmi <kmi> --allow-shell" : "--kmi <kmi>")
                 : (allow_shell ? "--allow-shell" : ""));
        execv(ksud_path, argv);
        /* execv 失败 */
        LOGE("execv('%s'): %s", ksud_path, strerror(errno));
        _exit(127);
    }
    /* 父进程等待 */
    int status = 0;
    while (waitpid(pid, &status, 0) < 0) {
        if (errno == EINTR) continue;
        LOGE("waitpid: %s", strerror(errno));
        return -1;
    }
    if (WIFEXITED(status)) {
        int code = WEXITSTATUS(status);
        if (code == 0) { LOGI("ksud late-load 退出码 0"); return 0; }
        LOGE("ksud late-load 退出码 %d", code);
        return -1;
    }
    if (WIFSIGNALED(status)) {
        LOGE("ksud late-load 被信号 %d 终止", WTERMSIG(status));
        return -1;
    }
    return -1;
}

/* ========================================================================
 * 策略 B：直接 insmod（用户提供 .ko，payload 自行 ELF 重定位）
 * ==================================================================== */

#ifndef __NR_init_module
#  ifdef __aarch64__
#    define __NR_init_module 105
#  else
#    define __NR_init_module 175
#  endif
#endif

static long ksu_init_module(void *image, size_t len, const char *params)
{
    return syscall(__NR_init_module, image, len, params);
}

/* 简易哈希表：未解析符号名 -> 符号在 buffer 中的偏移 */
#define HASH_CAP 2048
typedef struct { const char *name; size_t sym_off; int resolved; } hslot_t;
static hslot_t g_hash[HASH_CAP];

static unsigned hash_str(const char *s)
{
    unsigned h = 2166136261u;
    while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; }
    return h;
}
static void hash_insert(const char *name, size_t sym_off)
{
    unsigned h = hash_str(name) & (HASH_CAP - 1);
    for (size_t i = 0; i < HASH_CAP; i++) {
        hslot_t *slot = &g_hash[(h + i) & (HASH_CAP - 1)];
        if (slot->name == NULL) { slot->name = name; slot->sym_off = sym_off; slot->resolved = 0; return; }
        if (strcmp(slot->name, name) == 0) return;
    }
}
static hslot_t *hash_find(const char *name)
{
    unsigned h = hash_str(name) & (HASH_CAP - 1);
    for (size_t i = 0; i < HASH_CAP; i++) {
        hslot_t *slot = &g_hash[(h + i) & (HASH_CAP - 1)];
        if (slot->name == NULL) return NULL;
        if (strcmp(slot->name, name) == 0) return slot;
    }
    return NULL;
}

/* 收集 .ko 中所有 SHN_UNDEF 符号 */
static int collect_undef_symbols(uint8_t *buf, size_t buf_len)
{
    if (buf_len < sizeof(Elf64_Ehdr)) return -1;
    Elf64_Ehdr *eh = (Elf64_Ehdr *)buf;
    if (memcmp(eh->e_ident, ELFMAG, SELFMAG) != 0) return -1;
    if (eh->e_ident[EI_CLASS] != ELFCLASS64) return -1;
    Elf64_Shdr *shdrs = (Elf64_Shdr *)(buf + eh->e_shoff);
    Elf64_Sym *symtab = NULL;
    const char *strtab = NULL;
    size_t strtab_sz = 0, symtab_sz = 0, sym_entsize = 0;
    for (int i = 0; i < eh->e_shnum; i++) {
        if (shdrs[i].sh_type == SHT_SYMTAB) {
            symtab = (Elf64_Sym *)(buf + shdrs[i].sh_offset);
            symtab_sz = shdrs[i].sh_size;
            sym_entsize = shdrs[i].sh_entsize;
            uint32_t link = shdrs[i].sh_link;
            if (link < (uint32_t)eh->e_shnum && shdrs[link].sh_type == SHT_STRTAB) {
                strtab = (const char *)(buf + shdrs[link].sh_offset);
                strtab_sz = shdrs[link].sh_size;
            }
            break;
        }
    }
    if (!symtab || !strtab || sym_entsize != sizeof(Elf64_Sym)) return -1;
    size_t n = symtab_sz / sym_entsize;
    int undef_cnt = 0;
    for (size_t i = 0; i < n; i++) {
        Elf64_Sym *sym = &symtab[i];
        if (sym->st_shndx == SHN_UNDEF && sym->st_name < strtab_sz) {
            const char *name = strtab + sym->st_name;
            if (*name) { hash_insert(name, (uint8_t *)sym - buf); undef_cnt++; }
        }
    }
    LOGI("收集到 %d 个未解析符号", undef_cnt);
    return undef_cnt > 0 ? 0 : 1;
}

/* 从 /proc/kallsyms 解析符号地址（临时设 kptr_restrict=1） */
static int resolve_from_kallsyms(uint8_t *buf)
{
    char saved[16] = {0};
    int have_saved = 0;
    int fd = open("/proc/sys/kernel/kptr_restrict", O_RDONLY);
    if (fd >= 0) {
        if (read(fd, saved, sizeof(saved) - 1) > 0) have_saved = 1;
        close(fd);
        write_file("/proc/sys/kernel/kptr_restrict", "1");
    }
    FILE *fp = fopen("/proc/kallsyms", "r");
    if (!fp) { if (have_saved) write_file("/proc/sys/kernel/kptr_restrict", saved); return -1; }
    char line[512];
    int resolved_cnt = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *p = line;
        while (*p == ' ') p++;
        uint64_t addr = 0;
        if (*p == '0') { while (*p && *p != ' ') p++; }
        else { char *endp; addr = strtoull(p, &endp, 16); p = endp; }
        if (addr == 0) continue;
        while (*p == ' ') p++;
        if (*p) p++;
        while (*p == ' ') p++;
        char *name = p;
        char *e = name;
        while (*e && *e != ' ' && *e != '\t' && *e != '\n' && *e != '\r') e++;
        char saved_c = *e; *e = 0;
        if (*name) {
            hslot_t *slot = hash_find(name);
            if (slot && !slot->resolved) {
                Elf64_Sym *sym = (Elf64_Sym *)(buf + slot->sym_off);
                sym->st_shndx = SHN_ABS;
                sym->st_value = addr;
                slot->resolved = 1;
                resolved_cnt++;
            }
        }
        *e = saved_c;
    }
    fclose(fp);
    if (have_saved) write_file("/proc/sys/kernel/kptr_restrict", saved);
    LOGI("从 /proc/kallsyms 解析了 %d 个符号", resolved_cnt);
    return 0;
}

static int direct_insmod(const char *ko_path, int allow_shell)
{
    size_t ko_len = 0;
    uint8_t *buf = read_whole_file(ko_path, &ko_len);
    if (!buf) { LOGE("读取 .ko 失败: %s", ko_path); return -1; }
    LOGI("读取 .ko: %s (%zu 字节)", ko_path, ko_len);

    memset(g_hash, 0, sizeof(g_hash));
    int r = collect_undef_symbols(buf, ko_len);
    if (r == 0) {
        resolve_from_kallsyms(buf);
        int miss = 0;
        for (size_t i = 0; i < HASH_CAP; i++)
            if (g_hash[i].name && !g_hash[i].resolved) { LOGW("无法解析符号: %s", g_hash[i].name); miss++; }
        if (miss > 0) LOGW("有 %d 个符号未解析", miss);
    } else if (r == 1) {
        LOGI("无未解析符号，直接加载");
    } else {
        LOGE("ELF 解析失败");
        free(buf);
        return -1;
    }
    const char *params = allow_shell ? "allow_shell=1" : "";
    LOGI("调用 init_module（params='%s'）...", params);
    long ret = ksu_init_module(buf, ko_len, params);
    free(buf);
    if (ret < 0) { LOGE("init_module 失败: %s (errno=%d)", strerror(errno), errno); return -1; }
    return 0;
}

/* ---------- 重启 KernelSU Manager ---------- */
static void restart_manager(void)
{
    for (int i = 0; KSU_PACKAGES[i]; i++) {
        char cmd[256];
        snprintf(cmd, sizeof(cmd), "am force-stop %s 2>/dev/null", KSU_PACKAGES[i]);
        int rc = system(cmd); (void)rc;
        snprintf(cmd, sizeof(cmd),
                 "am start -n %s/me.weishu.kernelsu.ui.MainActivity 2>/dev/null",
                 KSU_PACKAGES[i]);
        rc = system(cmd); (void)rc;
    }
}

/* ---------- 主流程 ---------- */
static void usage(const char *prog)
{
    fprintf(stderr,
        "KernelSU 自动越狱 payload\n"
        "\n"
        "用法:\n"
        "  %s [选项]\n"
        "\n"
        "选项（策略 A：调用 ksud，推荐，自动适配所有版本）:\n"
        "  -p <ksud>     显式指定 ksud/libksud.so 路径\n"
        "  -k <kmi>      手动指定 KMI（如 android13-5.10）\n"
        "  -s            传入 allow_shell=1\n"
        "\n"
        "选项（策略 B：直接 insmod，需自备 .ko）:\n"
        "  -d <ko>       直接加载指定 .ko（跳过 ksud）\n"
        "\n"
        "通用选项:\n"
        "  -f            跳过 SELinux 强制模式检查\n"
        "  -n            不自动重启 Manager\n"
        "  -h            显示帮助\n",
        prog);
}

int main(int argc, char **argv)
{
    int allow_shell = 0, skip_selinux = 0, no_restart = 0;
    const char *manual_kmi = NULL;
    const char *ksud_path = NULL;
    const char *ko_path = NULL;

    int opt;
    while ((opt = getopt(argc, argv, "p:k:sd:fnh")) != -1) {
        switch (opt) {
        case 'p': ksud_path = optarg; break;
        case 'k': manual_kmi = optarg; break;
        case 's': allow_shell = 1; break;
        case 'd': ko_path = optarg; break;
        case 'f': skip_selinux = 1; break;
        case 'n': no_restart = 1; break;
        case 'h': usage(argv[0]); return 0;
        default: usage(argv[0]); return 1;
        }
    }

    LOGI("KernelSU 自动越狱 payload 启动");

    /* 1. SELinux 检查 */
    const char *se = get_selinux_status();
    LOGI("SELinux 状态: %s", se);
    if (!skip_selinux && strcmp(se, "Permissive") != 0) {
        LOGE("当前 SELinux 为 %s，非 Permissive 模式。", se);
        LOGE("与 Manager 越狱按钮一致，late-load 需 SELinux 宽容模式才能 insmod。");
        LOGE("如确需强行尝试，加 -f 参数。");
        return 2;
    }

    /* 2. 是否已加载 */
    if (has_kernelsu()) {
        LOGI("KernelSU 已加载，无需重复越狱。");
        if (!no_restart) restart_manager();
        return 0;
    }

    /* 3. 选择策略 */
    int success = 0;

    if (ko_path) {
        /* 策略 B：直接 insmod */
        LOGI("=== 策略 B：直接 insmod ===");
        if (direct_insmod(ko_path, allow_shell) == 0) {
            LOGI("init_module 成功");
            success = 1;
        }
    } else {
        /* 策略 A：调用 ksud late-load */
        LOGI("=== 策略 A：调用 ksud late-load ===");
        char ksud[PATH_MAX];
        if (locate_ksud(ksud_path, ksud, sizeof(ksud)) == 0) {
            LOGI("使用 ksud: %s", ksud);
            /* KMI：用户指定优先 */
            char kmi[64] = {0};
            const char *kmi_arg = manual_kmi;
            if (!kmi_arg) {
                if (detect_kmi(kmi, sizeof(kmi)) == 0) {
                    LOGI("检测到 KMI: %s", kmi);
                    kmi_arg = kmi;
                } else {
                    LOGW("KMI 自动检测失败，让 ksud 自行检测");
                }
            }
            if (run_ksud_late_load(ksud, kmi_arg, allow_shell) == 0) {
                LOGI("ksud late-load 成功");
                success = 1;
            } else {
                LOGW("ksud late-load 失败，可尝试 -d 直接指定 .ko");
            }
        } else {
            LOGE("无法定位 ksud，且未指定 .ko（-d）。请至少满足其一：");
            LOGE("  1. 设备已安装 KernelSU Manager（payload 会自动提取 ksud）");
            LOGE("  2. 通过 -p 指定 ksud 路径");
            LOGE("  3. 通过 -d 指定 .ko 路径");
        }
    }

    /* 4. 验证 */
    if (success) {
        if (has_kernelsu()) {
            LOGI("✓ 验证成功：KernelSU 已加载（越狱完成）");
        } else {
            LOGW("模块加载流程已完成，但探测 KernelSU 失败");
            LOGW("（可能 UAPI 不匹配或 ksud 内部加载失败，请查看 ksud 日志）");
        }
        if (!no_restart) {
            LOGI("重启 KernelSU Manager...");
            restart_manager();
        }
        LOGI("完成。打开 KernelSU Manager 即可见越狱模式。");
        return 0;
    }

    LOGE("越狱失败");
    return 1;
}
