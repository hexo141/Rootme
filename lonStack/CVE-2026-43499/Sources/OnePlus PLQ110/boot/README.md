# boot/

PLQ110 (OnePlus Ace 5 Pro / K3 regional) 关键 boot 镜像 — **已包含在 repo 内**（压缩形式）。

## 文件清单

| 文件 | 大小 | 用途 |
|------|------|------|
| `boot.img.xz` | ~10 MB | **完整 boot.img**（GKI kernel + ramdisk），xz 压缩；解压后即为标准 Android Boot Image v4 |
| `vmlinux.xz` | ~4 MB | 已从 boot.img 提取的 vmlinux ELF（嵌入于 kernel section 偏移 0x1099000） |
| `init_boot.img.xz` | ~2 MB | GKI init ramdisk（Android Boot Image v4） |
| `dtbo.img.xz` | ~140 KB | device tree overlay（稀疏，压缩率高） |
| `vbmeta.img` | 12 KB | AVB vbmeta（boot/init_boot） |
| `vbmeta_system.img` | 4 KB | AVB vbmeta（system/system_ext/product） |
| `vbmeta_vendor.img` | 4 KB | AVB vbmeta（vendor/vendor_dlkm/odm） |

合计 ~16 MB。

## 解压

```bash
cd boot
xz -dk boot.img.xz        # -d 解压, -k 保留 .xz
xz -dk vmlinux.xz
xz -dk init_boot.img.xz
xz -dk dtbo.img.xz
# vbmeta*.img 已是原始格式，不需要解压
```

## 校验 boot.img header

```bash
xxd boot.img | head -1
# 00000000: 414e 4452 4f49 4421 006a 2f02 ...  ->  ANDROID!

file vmlinux
# ELF 64-bit LSB shared object, ARM aarch64, stripped
```

## boot.img header 解析（PLQ110 实测）

```
magic           = ANDROID!
header_version  = 4            (Android Boot Image v4, GKI)
kernel_size     = 36,661,760   (35 MB)
ramdisk_size    = 0            (ramdisk 在 init_boot.img 中)
os_version      = 0x4
```

## vendor_boot.img（未包含，需自行提取）

vendor_boot.img 体积过大（96 MB），未包含在 repo 内。如需要，从设备提取：

```bash
adb shell su -c 'dd if=/dev/block/by-name/vendor_boot_a of=/sdcard/vendor_boot.img'
adb pull /sdcard/vendor_boot.img
```

vendor_boot header（实测）：
```
magic           = VNDRBOOT
header_version  = 4096         (v4)
cmdline         = "video=vfb:640x400,bpp=32,memsize=3072000 \
                   log_buf_len=2M nosoftlockup console=ttynull \
                   qcom_geni_serial.con_enabled=0 nohugevmalloc \
                   bootconfig buildvariant=user \
                   androidboot.hardware=qcom androidboot.memcg=1 \
                   androidboot.usbcontroller=a600000.dwc3 \
                   androidboot.load_modules_parallel=true \
                   androidboot.hypervisor.protected_vm.supported=true \
                   androidboot.vendor.qspa=true androidboot.serialconsole=0"
```

## 从 boot.img 提取 vmlinux（如需重新生成 `vmlinux.xz`）

使用仓库根目录的纯 Python 解包器（无外部依赖）：

```bash
# 假设已在 boot/ 目录下解压出 boot.img
python3 ../../tools/unpack_boot_pybootimg.py boot.img ./unpack-out
# 产物: ./unpack-out/kernel (arm64 Image, ~36MB)
#       ./unpack-out/vmlinux (嵌入 ELF, ~18MB)

# 重新压缩以节省空间
xz -9e unpack-out/vmlinux
# 产物 ≈ vmlinux.xz (~4 MB)
```
