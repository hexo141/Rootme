# bin/

预编译产物 — **已包含**，由 NDK r28b (clang 19.0.0) 在 dockcross/android-arm64 中编译。

## 二进制清单

| 文件 | 大小 | 来源 | 用途 |
|------|------|------|------|
| `qcom_exploit` | ~12 KB | `src/qcom_exploit.c` | 主漏洞利用 (Futex PI Race + Pipe PhysRW + dma-heap) |
| `run_exploit` | ~7 KB | `src/run_exploit.c` | exploit 入口 wrapper (execv qcom_exploit) |
| `kprobe` | ~8 KB | `src/kprobe.c` | 内核环境探测器 (maps / dma-heap / PR_SET_MM 可用性) |
| `hello` | ~6 KB | `src/hello.c` | NDK 工具链验证 |
| `test_dma_heap` | ~7 KB | `src/test_dma_heap.c` | /dev/dma_heap/* 测试 |
| `test_futex` | ~7 KB | `src/test_futex.c` | futex PI primitives 测试 |
| `test_min` | ~6 KB | `src/test_min.c` | 最小可执行测试 |
| `test_openat` | ~7 KB | `src/test_openat.c` | SELinux 路径访问性测试 |

所有二进制均为 ARM64 aarch64 PIE 可执行文件，已 strip。

```
$ file qcom_exploit
qcom_exploit: ELF 64-bit LSB pie executable, ARM aarch64, version 1 (SYSV),
              dynamically linked, interpreter /system/bin/linker64, stripped
```

## 重新编译

详见 `../DOCKER_WORKFLOW.md`。需要 Docker + `dockcross/android-arm64` 镜像。

最简命令：

```bash
docker pull dockcross/android-arm64

# 仓库根 = 包含 Rootme/ 的那一层
cd <path-to-repo-root>
docker run --rm -v "$PWD:/work" -w /work dockcross/android-arm64 bash -c '
SRC="/work/Rootme/CVE-2026-23274/OnePlus PLQ110/src"
BIN="/work/Rootme/CVE-2026-23274/OnePlus PLQ110/bin"
mkdir -p "$BIN" && cd "$SRC"
for f in qcom_exploit run_exploit kprobe hello test_dma_heap test_futex test_min test_openat; do
    $CC -O2 -pie -fPIE -I"$SRC/../target" -I"$SRC" -o "$BIN/$f" "${f}.c"
    strip "$BIN/$f"
done
'
```

## exploit.html 对此目录的依赖

`exploit.html` 在浏览器利用成功后，从相对路径 `bin/` 拉取以下三个文件部署到
设备的 `/data/local/tmp/qcom/`：

- `bin/run_exploit`
- `bin/qcom_exploit`
- `bin/kprobe`

如果这三个文件缺失，「运行 QCOM Kernel Exploit」按钮会失败。其他二进制
（hello / test_*）仅供离线调试，exploit.html 不会拉取。
