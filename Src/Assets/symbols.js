/*
 * symbols.js — Browser-side kallsyms symbol table extractor.
 *
 * Pure JavaScript port of the kallsyms-finding algorithm from
 *   https://github.com/marin-m/vmlinux-to-elf  (core/kallsyms.py)
 *
 * Only the symbol-extraction algorithm is ported. ELF generation,
 * vmlinuz decompression, the SQLite kernel DB lookups, ELF relocation
 * patching and the GUI are intentionally NOT ported. The only side
 * effect of this module is logging progress via the user-supplied
 * `log` callback and returning a structured result.
 *
 * Symbols of interest (mirrors Python output of `kallsyms_finder.py`):
 *   - kallsyms_token_table / token_index / markers / names / num_syms
 *   - kallsyms_addresses  (or  kallsyms_offsets + relative_base)
 *   - decoded symbol list: [{address: BigInt, type, name, isGlobal}]
 *
 * 64-bit kernel addresses can exceed Number.MAX_SAFE_INTEGER, so all
 * virtual addresses are represented as BigInt. 4-byte offsets stay as
 * Number for speed.
 *
 * Usage:
 *   import { extractKallsymsFromImage, formatSymbolsLikeNm } from './symbols.js';
 *   const result = await extractKallsymsFromImage(fileBuffer, {
 *     log: line => console.log(line),
 *   });
 *   const text = formatSymbolsLikeNm(result);
 *
 * Author: TRAE port of marin-m/vmlinux-to-elf. Algorithm credit: the
 * original author.
 */

'use strict';

/* ------------------------------------------------------------------ */
/* Tiny DataView-based byte reader                                     */
/* ------------------------------------------------------------------ */

class ByteReader {
  constructor(buf, byteOffset = 0, byteLength) {
    if (buf instanceof ArrayBuffer) {
      this.view = new DataView(buf, byteOffset, byteLength);
      this.buf = buf;
    } else if (ArrayBuffer.isView(buf)) {
      // Uint8Array etc.
      const off = buf.byteOffset + byteOffset;
      this.view = new DataView(buf.buffer, off, byteLength ?? buf.byteLength - byteOffset);
      this.buf = buf.buffer;
    } else {
      throw new TypeError('ByteReader expects ArrayBuffer or TypedArray');
    }
    this.length = this.view.byteLength;
  }

  u8(i)  { return this.view.getUint8(i); }
  i8(i)  { return this.view.getInt8(i); }

  u16(i, le = true)  { return this.view.getUint16(i, le); }
  i16(i, le = true)  { return this.view.getInt16(i, le); }

  u32(i, le = true)  { return this.view.getUint32(i, le); }
  i32(i, le = true)  { return this.view.getInt32(i, le); }

  // 64-bit reads always return BigInt (precision-safe).
  u64(i, le = true)  { return this.view.getBigUint64(i, le); }
  i64(i, le = true)  { return this.view.getBigInt64(i, le); }

  byte(i) { return this.view.getUint8(i); }
  slice(i, j) {
    return new Uint8Array(this.buf, this.view.byteOffset + i, Math.max(0, j - i));
  }

  /* bytes().find(needle, from=0) — returns index or -1 */
  find(needle, from = 0) {
    if (typeof needle === 'string') {
      const nb = new TextEncoder().encode(needle);
      return subarrayFind(this.view, nb, from);
    }
    return subarrayFind(this.view, needle, from);
  }

  /* rfind(needle, before) — returns index in [0, before) or -1 */
  rfind(needle, before) {
    if (typeof needle === 'string') needle = new TextEncoder().encode(needle);
    return subarrayRFind(this.view, needle, before);
  }
}

function subarrayFind(view, needle, from) {
  const n = needle.length;
  if (n === 0 || from + n > view.byteLength) return -1;
  // Naïve search; needle sizes here are tiny (<= 256 bytes).
  outer: for (let i = from; i + n <= view.byteLength; i++) {
    for (let k = 0; k < n; k++) {
      if (view.getUint8(i + k) !== needle[k]) continue outer;
    }
    return i;
  }
  return -1;
}

function subarrayRFind(view, needle, before) {
  const n = needle.length;
  if (n === 0 || before > view.byteLength) before = view.byteLength;
  if (before < n) return -1;
  outer: for (let i = before - n; i >= 0; i--) {
    for (let k = 0; k < n; k++) {
      if (view.getUint8(i + k) !== needle[k]) continue outer;
    }
    return i;
  }
  return -1;
}

/* Decode ASCII bytes [i, j) to a string. */
function ascii(view, i, j) {
  let s = '';
  for (; i < j; i++) s += String.fromCharCode(view.getUint8(i));
  return s;
}

/* Bytes-to-latin1 string (each byte → U+0000..U+00FF) for regex work. */
function bytesToLatin1(view, i, j) {
  let s = '';
  for (; i < j; i++) s += String.fromCharCode(view.getUint8(i));
  return s;
}

/* ------------------------------------------------------------------ */
/* Android boot.img header parser                                      */
/* ------------------------------------------------------------------ */

const BOOT_MAGIC = 'ANDROID!';

/**
 * Parse an Android boot.img header and return the raw kernel bytes.
 *
 * Supports boot image header versions v0/v1/v2 (legacy, with embedded
 * page_size) and v3/v4 (page_size fixed to 4096). For arm64 Image payloads
 * we additionally honour the embedded `image_size` field (header offset 16)
 * so appended DTBs and padding are not fed to the kallsyms scanner.
 */
function parseAndroidBootImage(buf) {
  if (!(buf instanceof Uint8Array)) buf = new Uint8Array(buf);
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  const r = new ByteReader(buf);

  // Check "ANDROID!" magic at offset 0.
  if (ascii(view, 0, 8) !== BOOT_MAGIC) {
    return null; // not a boot.img; caller will treat the buffer as raw.
  }

  const kernelSize   = r.u32(0x08);
  const headerSize   = r.u32(0x14);
  const headerVer    = r.u32(0x28) & 0xffff; // top nibbles reserved
  const pageSize     = headerVer >= 3 ? 4096 : r.u32(0x24) || 4096;

  // Kernel begins right after the header page(s). v3/v4 use header_size
  // aligned up to page_size; v0/v1/v2 fit the header in one page.
  const kernelOffset = headerVer >= 3
    ? alignUp(headerSize, pageSize)
    : pageSize;

  if (kernelOffset + kernelSize > buf.byteLength) {
    throw new Error(`boot.img: kernel region [0x${kernelOffset.toString(16)}, 0x${(kernelOffset+kernelSize).toString(16)}) extends past file end (0x${buf.byteLength.toString(16)})`);
  }

  // arm64 Image header: text_offset@0x08, image_size@0x10, flags@0x18.
  // Use image_size if it is sane and not larger than kernelSize.
  let imageBytes = buf.subarray(kernelOffset, kernelOffset + kernelSize);
  if (kernelSize >= 0x20 && ascii(view, kernelOffset + 0x38, kernelOffset + 0x3c) === 'ARMd') {
    const arm64ImageSize = Number(r.u64(kernelOffset + 0x10));
    if (arm64ImageSize > 0 && arm64ImageSize <= kernelSize) {
      imageBytes = buf.subarray(kernelOffset, kernelOffset + arm64ImageSize);
    }
  }
  return { image: imageBytes, kernelOffset, pageSize, headerVer, kernelSize };
}

function alignUp(v, alignment) {
  const m = v % alignment;
  return m === 0 ? v : v + (alignment - m);
}

/* ------------------------------------------------------------------ */
/* Architecture detection (regex on byte stream)                       */
/* ------------------------------------------------------------------ */

const ARCH_PROLOGUES = {
  // Each pattern is a JS RegExp operating on a latin1-encoded string.
  mipsle:     /.\xff\xbd\x27..[\xa0-\xbf]\xaf/gs,
  mipsbe:     /\x27\xbd\xff.\xaf[\xa0-\xbf]../gs,
  mips64le:   /.\xff\xbd\x67..[\xa0-\xbf]\xff/gs,
  mips64be:   /\x67\xbd\xff.\xff[\xa0-\xbf]../gs,
  x86:        /\x55\x89\xe5(?:\x83\xec|\x57\x56)/gs,
  x86_64:     /\x55\x48\x89\xe5/gs,
  powerpcbe:  /\x7c\x08\x02\xa6/gs,
  powerpcle:  /\xa6\x02\x08\x7c/gs,
  armbe:      /\xe9\x2d..(?:[\xe0-\xef]...){2}/gs,
  armle:      /\x2d\xe9(?:...[\xe0-\xef]){2}/gs,
  mips16e:    /\xf0\x08\x64.\x01./gs,
  superhle:   /\xf6\x69\x0b\x00\xf6\x68/gs,
  superhbe:   /\x69\xf6\x00\x0b\x68\xf6/gs,
  aarch64:    /\xc0\x03\x5f\xd6/gs, // RET, an epilogue
  sparc:      /\x81\xc7\xe0\x08\x81\xe8/gs,
  arcompact:  /\xf1\xc0.\x1c\x48[\xb0-\xbf]/gs,
};

const ARCH_TO_NAME = {
  mipsle:     'Little-endian MIPS',
  mipsbe:     'Big-endian MIPS',
  mips64le:   'Little-endian MIPS64',
  mips64be:   'Big-endian MIPS64',
  x86:        '32-bit x86',
  x86_64:     '64-bit x86',
  powerpcbe:  'Big-endian PowerPC',
  powerpcle:  'Little-endian PowerPC',
  armbe:      'Big-endian ARM',
  armle:      'Little-endian ARM',
  mips16e:    'Big-endian MIPS16e',
  superhle:   'Little-endian SuperH',
  superhbe:   'Big-endian SuperH',
  sparc:      'SPARC',
  arcompact:  'ARCompact',
  aarch64:    'Little-endian ARM64',
};

function guessArchitecture(img) {
  // Special-case: UEFI PE stub on ARM64 (image starts with "MZ", ARMd at 0x38).
  if (img[0] === 0x4d && img[1] === 0x5a && ascii(new DataView(img.buffer, img.byteOffset, img.byteLength), 0x38, 0x3c) === 'ARMd') {
    return { name: 'aarch64', is64Bit: true, isBigEndian: false };
  }

  const s = bytesToLatin1(new DataView(img.buffer, img.byteOffset, img.byteLength), 0, img.byteLength);
  let best = null, bestCount = 0;
  for (const [name, regex] of Object.entries(ARCH_PROLOGUES)) {
    const m = s.match(regex);
    const count = m ? m.length : 0;
    if (count > bestCount) { bestCount = count; best = name; }
  }
  if (bestCount < 100 || !best) {
    throw new Error('The architecture could not be guessed successfully (need >= 100 prologue matches).');
  }
  // 64-bit heuristic per-arch.
  const is64Bit = best === 'aarch64' || best === 'x86_64' || best === 'mips64le' || best === 'mips64be';
  const isBigEndian = best === 'mipsbe' || best === 'mips64be' || best === 'powerpcbe' || best === 'armbe' || best === 'superhbe';
  return { name: best, is64Bit, isBigEndian };
}

/* ------------------------------------------------------------------ */
/* KallsymsFinder                                                      */
/* ------------------------------------------------------------------ */

class KallsymsNotFoundException extends Error {}

class KallsymsFinder {
  /**
   * @param {Uint8Array} kernelImg raw kernel image bytes
   * @param {object} opts
   *   - log(msg)        progress callback (default no-op)
   *   - bitSize         32 or 64 (default: auto-detect)
   *   - useAbsolute     assume offsets are absolute addresses
   *   - baseAddress     override the relative base / kernel text base
   */
  constructor(kernelImg, opts = {}) {
    this.img = kernelImg instanceof Uint8Array ? kernelImg : new Uint8Array(kernelImg);
    this.r = new ByteReader(this.img);
    this.log = opts.log || (() => {});

    if (opts.bitSize) {
      if (opts.bitSize !== 32 && opts.bitSize !== 64) {
        throw new Error('Please specify a register bit size of either 32 or 64 bits');
      }
      this.is64Bits = opts.bitSize === 64;
    } else {
      this.is64Bits = null;
    }

    this.overrideRelativeBase = !!opts.useAbsolute;
    this.explicitBaseAddress = opts.baseAddress != null ? BigInt(opts.baseAddress) : null;
    this.kernelTextCandidate = null;

    // Filled in by find_* methods:
    this.kallsymsTokenTableOffset = null;
    this.kallsymsTokenIndexOffset = null;
    this.kallsymsTokenIndexEndOffset = null;
    this.kallsymsMarkersOffset = null;
    this.kallsymsNamesOffset = null;
    this.kallsymsNumSymsOffset = null;
    this.kallsymsAddressesOrOffsetsOffset = null;
    this.offsetTableElementSize = null;
    this.uncompressedKallsyms = false;

    this.versionString = null;
    this.versionNumber = null;
    this.architecture = null;
    this.elfMachine = null;
    this.isBigEndian = null;

    this.numSymbols = 0;
    this.symbolNames = null;
    this.symbolAddresses = null;
    this.kernelAddresses = null;
    this.symbols = null;

    this.hasBaseRelative = false;
    this.hasAbsolutePercpu = false;
    this.relativeBaseAddress = null;
  }

  /* ---------------- public entrypoint ---------------- */

  run() {
    this.findLinuxKernelVersion();
    this.guessArchitecture();
    try {
      this.findKallsymsTokenTable();
      this.findKallsymsTokenIndex();
      this.uncompressedKallsyms = false;
    } catch (firstErr) {
      if (!(firstErr instanceof KallsymsNotFoundException)) throw firstErr;
      try {
        this.findKallsymsNamesUncompressed();
        this.findKallsymsMarkersUncompressed();
        this.uncompressedKallsyms = true;
      } catch (secondErr) {
        throw firstErr;
      }
    }

    if (!this.uncompressedKallsyms) {
      this.findKallsymsMarkers();
      this.findKallsymsNames();
    }
    this.findKallsymsNumSyms();
    this.findKallsymsAddressesOrSymbols();
    this.parseSymbolTable();
    if (this.kernelTextCandidate === null) {
      this.inferBaseAddressFromSyms();
    }
  }

  /* ---------------- step 1: kernel version ---------------- */

  findLinuxKernelVersion() {
    // `Linux version <X.Y.Z> <printable-ascii>` — capture group 1 = number.
    const s = bytesToLatin1(this.r.view, 0, this.img.byteLength);
    const m = s.match(/Linux version (\d+\.[\d.]*\d)[ -~]+/);
    if (!m) throw new Error('No version string found in this kernel');
    this.versionString = m[0];
    this.versionNumber = m[1];
    this.log(`[+] Version string: ${this.versionString}`);

    const archStr = s.match(/mod_unload[ -~]+/);
    if (archStr && archStr[0].trim().split(/\s+/).length > 2) {
      this.log(`[+]   Architecture string: ${archStr[0]}`);
    }
  }

  /* ---------------- step 2: architecture ---------------- */

  guessArchitecture() {
    try {
      const guess = guessArchitecture(this.img);
      this.architecture = guess.name;
      if (this.is64Bits === null) this.is64Bits = guess.is64Bit;
      this.isBigEndian = guess.isBigEndian;
      this.log(`[+] Guessed architecture: ${ARCH_TO_NAME[guess.name] || guess.name}`);
    } catch (e) {
      if (this.is64Bits === null) throw e;
    }
  }

  /* ---------------- step 3: kallsyms_token_table ---------------- */

  findKallsymsTokenTable() {
    // Look for the contiguous block "0\0 1\0 2\0 ... 9\0".
    const sequence = new Uint8Array(20);
    for (let i = 0; i < 10; i++) { sequence[i*2] = 0x30 + i; sequence[i*2+1] = 0; }
    const sequencesToAvoid = [
      new Uint8Array([0x3a, 0]), new Uint8Array([0, 0]),
      new Uint8Array([0, 1]), new Uint8Array([0, 2]),
      new Uint8Array([0x41, 0x53, 0x43, 0x49, 0x49, 0]),
    ];

    let candidates = [];
    let candidatesFollowedWithAscii = [];
    let position = 0;
    while (true) {
      position = this.r.find(sequence, position + 1);
      if (position === -1) break;
      let avoidHit = false;
      const tail = position + sequence.length;
      for (const seq of sequencesToAvoid) {
        if (tail + seq.length > this.img.byteLength) continue;
        let ok = true;
        for (let k = 0; k < seq.length; k++) {
          if (this.img[tail + k] !== seq[k]) { ok = false; break; }
        }
        if (ok) { avoidHit = true; break; }
      }
      if (avoidHit) continue;
      candidates.push(position);
      // "followed with ASCII" check.
      if (tail < this.img.byteLength) {
        const ch = this.img[tail];
        if ((ch >= 0x30 && ch <= 0x39) || (ch >= 0x41 && ch <= 0x5a) || (ch >= 0x61 && ch <= 0x7a)) {
          candidatesFollowedWithAscii.push(position);
        }
      }
    }

    if (candidates.length !== 1) {
      if (candidatesFollowedWithAscii.length === 1) {
        candidates = candidatesFollowedWithAscii;
      } else if (candidates.length === 0) {
        throw new KallsymsNotFoundException(`${candidates.length} candidates for kallsyms_token_table in kernel image`);
      } else {
        throw new Error(`${candidates.length} candidates for kallsyms_token_table in kernel image`);
      }
    }
    position = candidates[0];

    // Walk backwards past tokens '0'..'/' (256 - ord('0') tokens).
    let currentIdx = 0x30; // ord('0')
    position -= 1;
    if (position < 0 || this.img[position] !== 0) {
      throw new Error('This structure is not a kallsyms_token_table');
    }
    for (let t = 0; t < currentIdx; t++) {
      for (let c = 0; c < 50; c++) {
        position -= 1;
        if (position < 0) throw new Error('This structure is not a kallsyms_token_table');
        const b = this.img[position];
        if (b === 0 || b > 0x7a) break; // terminator or high-range char
        if (c >= 49) throw new Error('This structure is not a kallsyms_token_table');
      }
    }
    position += 1;
    position += -position % 4; // align to 4 bytes

    this.kallsymsTokenTableOffset = position;
    this.log(`[+] Found kallsyms_token_table at file offset 0x${position.toString(16).padStart(8, '0')}`);
  }

  /* ---------------- step 4: kallsyms_token_index ---------------- */

  findKallsymsTokenIndex() {
    // Walk forward through 256 null-terminated tokens; record their offsets.
    let position = this.kallsymsTokenTableOffset;
    const allTokenOffsets = [];
    position -= 1;

    for (let t = 0; t < 256; t++) {
      position += 1;
      allTokenOffsets.push(position - this.kallsymsTokenTableOffset);
      for (let c = 0; c < 50; c++) {
        position += 1;
        if (position >= this.img.byteLength) throw new Error('This structure is not a kallsyms_token_table');
        if (this.img[position] === 0) break;
        if (c >= 49) throw new Error('This structure is not a kallsyms_token_table');
      }
    }

    // Build LE/BE candidate byte patterns and search for them right after.
    const MAX_ALIGNMENT = 256;
    const KALLSYMS_TOKEN_INDEX_SIZE = 256 * 2;
    const searchStart = position;
    const searchEnd = Math.min(this.img.byteLength, position + KALLSYMS_TOKEN_INDEX_SIZE + MAX_ALIGNMENT);

    const leBytes = new Uint8Array(allTokenOffsets.length * 2);
    const beBytes = new Uint8Array(allTokenOffsets.length * 2);
    for (let i = 0; i < allTokenOffsets.length; i++) {
      const v = allTokenOffsets[i];
      leBytes[i*2]   = v & 0xff;
      leBytes[i*2+1] = (v >> 8) & 0xff;
      beBytes[i*2]   = (v >> 8) & 0xff;
      beBytes[i*2+1] = v & 0xff;
    }
    const lePos = subarrayFind(this.r.view, leBytes, searchStart);
    const bePos = subarrayFind(this.r.view, beBytes, searchStart);

    if (lePos === -1 && bePos === -1) {
      throw new Error('The value of kallsyms_token_index was not found');
    } else if (lePos > bePos) {
      this.isBigEndian = false;
      this.kallsymsTokenIndexOffset = lePos;
    } else if (bePos > lePos) {
      this.isBigEndian = true;
      this.kallsymsTokenIndexOffset = bePos;
    } else {
      // lePos === bePos, both found at same position (only possible for null pattern)
      throw new Error('The value of kallsyms_token_index was not found');
    }
    this.kallsymsTokenIndexEndOffset = this.kallsymsTokenIndexOffset + leBytes.length;
    this.log(`[+] Found kallsyms_token_index at file offset 0x${this.kallsymsTokenIndexOffset.toString(16).padStart(8, '0')}`);
  }

  /* ---------------- step 5: kallsyms_markers ---------------- */

  findKallsymsMarkers() {
    // Try element sizes 8, 4, 2; pick the first that looks like a sorted,
    // 0-prefixed marker table with sane 0x200..0x40000 jumps.
    const le = !this.isBigEndian;
    for (const size of [8, 4, 2]) {
      let position = this.kallsymsTokenTableOffset;
      for (let attempt = 0; attempt < 32; attempt++) {
        const found = this.r.rfind(new Uint8Array(size), position);
        if (found === -1) break;
        position = found;
        position -= position % size;
        if (position + 4 * size > this.img.byteLength) continue;

        // Read 4 entries.
        const entries = [
          readUIntN(this.r, position + 0*size, size, le),
          readUIntN(this.r, position + 1*size, size, le),
          readUIntN(this.r, position + 2*size, size, le),
          readUIntN(this.r, position + 3*size, size, le),
        ];
        if (entries[0] !== 0) continue;
        let ok = true;
        for (let i = 1; i < entries.length; i++) {
          if (!(entries[i-1] + 0x200 < entries[i] && entries[i] < entries[i-1] + 0x40000)) { ok = false; break; }
        }
        if (ok) {
          this.kallsymsMarkersOffset = position;
          this.offsetTableElementSize = size;
          this.log(`[+] Found kallsyms_markers at file offset 0x${position.toString(16).padStart(8, '0')}`);
          return;
        }
      }
    }
    throw new Error('Could not find kallsyms_markers');
  }

  /* ---------------- step 6: kallsyms_names (estimate) ---------------- */

  findKallsymsNames() {
    const le = !this.isBigEndian;
    const size = this.offsetTableElementSize;

    let numEntries = Math.floor(
      (this.kallsymsTokenTableOffset - this.kallsymsMarkersOffset) / size
    );
    if (numEntries > 3000) numEntries = 3000;

    const markers = [];
    for (let i = 0; i < numEntries; i++) {
      markers.push(readUIntN(this.r, this.kallsymsMarkersOffset + i * size, size, le));
    }
    // Trim entries that violate the 0x200..0x40000 monotonic constraint.
    for (let i = 1; i < markers.length; i++) {
      if (!(markers[i-1] + 0x200 < markers[i] && markers[i] < markers[i-1] + 0x40000)) {
        markers.length = i;
        break;
      }
    }
    let lastNonZero = 0;
    for (const m of markers) if (m !== 0) lastNonZero = m;

    let position = this.kallsymsMarkersOffset - lastNonZero;
    position += -position % size;
    if (position <= 0) throw new Error('kallsyms_names position invalid');
    this.kallsymsNamesOffset = position;
  }

  /* ---------------- step 7: kallsyms_num_syms ---------------- */

  findKallsymsNumSyms() {
    const tokenTable = this.getTokenTable();
    const possibleSymbolTypes = 'ABDRTVWGNPCSU-?uvw'.split('');
    const le = !this.isBigEndian;
    const size = this.offsetTableElementSize;

    let needle = -1;
    const alreadyExplored = []; // dynamic-programming memo

    while (needle === -1) {
      // The first token of the first symbol must be a valid nm type letter.
      if (this.kallsymsNamesOffset + 1 >= this.img.byteLength) {
        this.kallsymsNamesOffset -= 4;
        if (this.kallsymsNamesOffset < 0) throw new Error('Could not find kallsyms_names');
        continue;
      }
      const firstTokenIdx = this.img[this.kallsymsNamesOffset + 1];
      const firstToken = tokenTable[firstTokenIdx] || '';
      const firstChar = firstToken[0] || '';
      const lower = firstChar.toLowerCase();
      const isWeak = (lower === 'u' || lower === 'v' || lower === 'w');
      const isType = possibleSymbolTypes.includes(firstChar.toUpperCase()) ||
                     (isWeak && possibleSymbolTypes.includes(lower));
      if (!isType) {
        this.kallsymsNamesOffset -= 4;
        if (this.kallsymsNamesOffset < 0) throw new Error('Could not find kallsyms_names');
        continue;
      }

      // DP forward scan from kallsyms_names_offset up to kallsyms_markers_offset.
      const base = this.kallsymsNamesOffset;
      const end  = this.kallsymsMarkersOffset;
      alreadyExplored.length = 0;
      for (let off = 0; off <= end - base; off++) {
        const nextByte = this.img[end - off];
        let symbolSize;
        if (nextByte & 0x80) {
          const lo = nextByte & 0x7f;
          const hi = this.img[end - off + 1];
          symbolSize = (lo | (hi << 7)) + 2;
        } else {
          symbolSize = nextByte + 1;
        }
        const nextHop = off - symbolSize;
        if (nextByte === 0) {
          alreadyExplored.push(off <= 256 ? 0 : -1);
        } else if (nextHop < 0 || alreadyExplored[nextHop] === -1) {
          alreadyExplored.push(-1);
        } else {
          alreadyExplored.push(alreadyExplored[nextHop] + 1);
        }
      }
      const numSymbols = alreadyExplored[alreadyExplored.length - 1];

      if (numSymbols < 256) {
        this.kallsymsNamesOffset -= 4;
        if (this.kallsymsNamesOffset < 0) throw new Error('Could not find kallsyms_names');
        continue;
      }

      this.numSymbols = numSymbols;

      // Find the encoded num_symbols long right before kallsyms_names_offset.
      const encoded = encodeUIntN(numSymbols, size, le);
      const MAX_ALIGNMENT = 256;
      const searchStart = Math.max(0, this.kallsymsNamesOffset - MAX_ALIGNMENT - 20);
      needle = this.r.rfind(encoded, this.kallsymsNamesOffset);
      if (needle === -1 || needle < searchStart) {
        needle = -1;
        this.kallsymsNamesOffset -= 4;
        if (this.kallsymsNamesOffset < 0) throw new Error('Could not find kallsyms_names');
      }
    }

    this.log(`[+] Found kallsyms_names at file offset 0x${this.kallsymsNamesOffset.toString(16).padStart(8, '0')} (${this.numSymbols} symbols)`);
    this.kallsymsNumSymsOffset = needle;
    this.log(`[+] Found kallsyms_num_syms at file offset 0x${needle.toString(16).padStart(8, '0')}`);
  }

  /* ---------------- step 8: kallsyms_addresses / offsets ---------------- */

  findKallsymsAddressesOrSymbols() {
    const [major, minor] = this.versionNumber.split('.').map(n => parseInt(n, 10));

    // CONFIG_KALLSYMS_BASE_RELATIVE for v4.6+ non-ia64.
    const likelyHasBaseRelative =
      (major > 4 && major < 7) || (major === 4 && minor >= 6) &&
      !/ia64|itanium/i.test(this.versionString);

    const likelyIs64Bits = this.is64Bits;

    // Heuristic search parameters: [hasBaseRelative, pcRelative, canSkip].
    let params;
    if (major >= 7) {
      params = [[false, true, true], [false, false, false]];
    } else {
      params = likelyHasBaseRelative
        ? [[true, false, true], [false, false, false]]
        : [[false, false, true], [false, false, false]];
      if (this.overrideRelativeBase) params = [[false, false, false]];
    }

    const le = !this.isBigEndian;

    for (const [hasBaseRelative, pcRelative, canSkip] of params) {
      const addressByteSize = likelyIs64Bits ? 8 : this.offsetTableElementSize;
      const offsetByteSize = Math.min(4, this.offsetTableElementSize);

      let position;
      if (major > 6 || (major === 6 && minor >= 4)) {
        // Linux 6.4+: addresses/offsets come after kallsyms_token_index.
        const alignSize = (likelyIs64Bits && !pcRelative) ? 8 : 4;
        position = this.kallsymsTokenIndexEndOffset;
        position += -position % alignSize;
        if (hasBaseRelative) {
          position += this.numSymbols * offsetByteSize;
          position += -position % alignSize;
          position += addressByteSize;
        } else if (pcRelative) {
          position += this.numSymbols * offsetByteSize;
        } else {
          position += this.numSymbols * addressByteSize;
        }
      } else {
        position = this.kallsymsNumSymsOffset;
      }

      // Skip leading zero-address words.
      while (position > addressByteSize) {
        let allZero = true;
        for (let k = 0; k < addressByteSize; k++) {
          if (this.img[position - addressByteSize + k] !== 0) { allZero = false; break; }
        }
        if (!allZero) break;
        position -= addressByteSize;
      }

      if (hasBaseRelative) {
        this.hasBaseRelative = true;
        position -= addressByteSize;
        this.relativeBaseAddress = readUIntNBig(this.r, position, addressByteSize, le);
        // Skip preceding zero-offset words.
        while (position > offsetByteSize) {
          let allZero = true;
          for (let k = 0; k < offsetByteSize; k++) {
            if (this.img[position - offsetByteSize + k] !== 0) { allZero = false; break; }
          }
          if (!allZero) break;
          position -= offsetByteSize;
        }
        position -= this.numSymbols * offsetByteSize;
      } else if (pcRelative) {
        position -= this.numSymbols * offsetByteSize;
        this.hasBaseRelative = false;
      } else {
        this.hasBaseRelative = false;
        position -= this.numSymbols * addressByteSize;
      }
      this.kallsymsAddressesOrOffsetsOffset = position;

      // Read the table as a typed array of N values.
      let values;
      if (hasBaseRelative) {
        // offsets are signed (may be negative)
        values = readSignedArray(this.r, position, this.numSymbols, offsetByteSize, le);
        // monotonicity sanity check
        if (canSkip && values.length >= 3) {
          if (!(values[0] <= values[1] && values[1] <= values[2])) continue;
        }
      } else if (pcRelative) {
        values = readSignedArray(this.r, position, this.numSymbols, offsetByteSize, le);
      } else {
        values = readUnsignedArray(this.r, position, this.numSymbols, addressByteSize, le);
      }

      // Heuristics + statistics mirroring kallsyms.py.
      if (hasBaseRelative) {
        const negativeItems = values.filter(v => v < 0).length;
        const BITS = this.is64Bits ? 64 : 32;
        const NEG_MASK = BigInt(0xfff) << BigInt(BITS - 12);
        const ABS_MASK = BigInt(0x3f) << BigInt(BITS - 8);
        const heuristicallyNegative = values.filter(v => (BigInt(v) & NEG_MASK) === NEG_MASK).length;
        const heuristicallyAbsolute = values.filter(v => (BigInt(v) & ABS_MASK) === BigInt(0)).length;
        const negPct = heuristicallyNegative / values.length;
        const absPct = heuristicallyAbsolute / values.length;
        if (negPct < 0.5) {
          this.log(`[!] WARNING: Less than half (${Math.trunc(negPct * 100)}%) of offsets are negative`);
          this.log(`             You may want to re-run this utility, overriding the relative base`);
        }
        if (absPct > 0.5) {
          this.log(`[!] WARNING: More than half (${Math.trunc(absPct * 100)}%) of offsets look like absolute addresses`);
          this.log(`[!]          You may want to re-run this utility, overriding the relative base`);
        }
        if (absPct > 0.5 || negPct < 0.5) {
          this.log(`[+] Note: sometimes there is junk at the beginning of the kernel, and the load address is not the guessed`);
          this.log(`          base address. You may need to play around with different load addresses to get everything`);
          this.log(`          to line up. There may be some decent tables in the kernel with known patterns that could be`);
          this.log(`          used to line things up heuristically, but this has not been explored this yet.`);
        }
        this.log(`[+] Negative offsets overall: ${Math.trunc(negativeItems / values.length * 100)}%`);

        if (negativeItems / values.length >= 0.5) {
          // CONFIG_KALLSYMS_ABSOLUTE_PERCPU: negative offsets → relative_base-1-offset.
          this.hasAbsolutePercpu = true;
          const rb = this.relativeBaseAddress;
          this.kernelAddresses = values.map(v =>
            v < 0 ? rb - 1n - BigInt(v) : BigInt(v)
          );
        } else {
          this.hasAbsolutePercpu = false;
          const rb = this.relativeBaseAddress;
          this.kernelAddresses = values.map(v => BigInt(v) + rb);
        }
      } else if (pcRelative) {
        const _text = values[0];
        const last = values[values.length - 1];
        if (!(_text <= 0 && last >= 0) && canSkip) continue;
        // Read base address from ELF program header (aarch64 Image only).
        const addrMarker = addressByteSize === 8 ? 'Q' : 'I';
        const phdrOffset = readUIntN(this.r, 0x18 + addressByteSize, addressByteSize, le) + (this.is64Bits ? 0x10 : 0x08);
        const baseAddress = readUIntN(this.r, phdrOffset, addressByteSize, le);
        this.hasAbsolutePercpu = false;
        this.kernelAddresses = values.map((v, i) =>
          BigInt(baseAddress) + BigInt(v) - BigInt(_text) + BigInt(i) * BigInt(offsetByteSize)
        );
      } else {
        this.hasAbsolutePercpu = false;
        this.kernelAddresses = values.map(v => BigInt(v));
      }

      const nullItems = this.kernelAddresses.filter(a => a === 0n).length;
      this.log(`[+] Null addresses overall: ${Math.trunc(nullItems / values.length * 100)}%`);
      if (nullItems / values.length >= 0.2 && canSkip) continue;

      this.log(`[+] Found ${this.hasBaseRelative ? 'kallsyms_offsets' : 'kallsyms_addresses'} at file offset 0x${position.toString(16).padStart(8, '0')}`);
      return;
    }
    throw new Error('Could not find kallsyms_addresses or kallsyms_offsets');
  }

  /* ---------------- step 9: symbol table parse ---------------- */

  getTokenTable() {
    if (!this.uncompressedKallsyms) {
      const tokens = [];
      let position = this.kallsymsTokenTableOffset;
      for (let i = 0; i < 256; i++) {
        let token = '';
        while (position < this.img.byteLength && this.img[position] !== 0) {
          token += String.fromCharCode(this.img[position]);
          position++;
        }
        position++; // skip NUL
        tokens.push(token);
      }
      return tokens;
    }
    // Uncompressed kallsyms: tokens are just the bare byte values.
    return Array.from({ length: 256 }, (_, i) => String.fromCharCode(i));
  }

  parseSymbolTable() {
    const tokens = this.getTokenTable();
    const names = [];
    let position = this.kallsymsNamesOffset;
    for (let n = 0; n < this.numSymbols; n++) {
      let length = this.img[position++];
      if (length & 0x80) {
        length = (length & 0x7f) | (this.img[position++] << 7);
      }
      let name = '';
      for (let i = 0; i < length; i++) {
        const idx = this.img[position++];
        name += tokens[idx] || '';
      }
      names.push(name);
    }
    this.symbolNames = names;

    const symbols = [];
    for (let i = 0; i < this.kernelAddresses.length; i++) {
      const name = names[i] || '';
      const typeChar = name[0] || '?';
      const lower = typeChar.toLowerCase();
      const isWeak = lower === 'u' || lower === 'v' || lower === 'w';
      const symbolType = typeChar;            // keep original case for output (matches Python print_symbols_debug)
      const isGlobal = isWeak ? true : typeChar === typeChar.toUpperCase() && typeChar !== typeChar.toLowerCase();
      symbols.push({
        address: this.kernelAddresses[i],
        type: symbolType,
        name: name.slice(1),
        isGlobal,
      });
    }
    this.symbols = symbols;
  }

  /* ---------------- step 10: base address fallback ---------------- */

  inferBaseAddressFromSyms() {
    const firstText = this.symbols.find(s => s.type === 'T');
    const firstSymAddr = firstText ? firstText.address : null;

    if (this.hasBaseRelative && this.relativeBaseAddress < firstSymAddr) {
      this.kernelTextCandidate = this.relativeBaseAddress & ~0x1fffn;
      if (this.kernelTextCandidate !== this.relativeBaseAddress) {
        this.log(`[+] Guessed the base address using the kallsyms_relative_base value (0x${this.relativeBaseAddress.toString(16)} aligned to 0x${this.kernelTextCandidate.toString(16)})`);
      } else {
        this.log(`[+] Guessed the base address using the kallsyms_relative_base value (0x${this.kernelTextCandidate.toString(16)})`);
      }
    } else {
      this.kernelTextCandidate = firstSymAddr & ~0x1fffn;
      this.log(`[+] Guessed the base address using the first_symbol_virtual_address fallback heuristic (0x${this.kernelTextCandidate.toString(16)})`);
    }
  }
}

/* ------------------------------------------------------------------ */
/* Numeric helpers                                                     */
/* ------------------------------------------------------------------ */

function readUIntN(reader, off, size, le) {
  if (size === 1) return reader.u8(off);
  if (size === 2) return reader.u16(off, le);
  if (size === 4) return reader.u32(off, le);
  if (size === 8) return Number(reader.u64(off, le));
  throw new Error(`bad size ${size}`);
}

function readSignedN(reader, off, size, le) {
  if (size === 1) return reader.i8(off);
  if (size === 2) return reader.i16(off, le);
  if (size === 4) return reader.i32(off, le);
  if (size === 8) return Number(reader.i64(off, le));
  throw new Error(`bad size ${size}`);
}

// BigInt-valued unsigned read; safe for full 64-bit addresses.
function readUIntNBig(reader, off, size, le) {
  if (size === 8) return reader.u64(off, le);
  return BigInt(readUIntN(reader, off, size, le));
}

function readSignedArray(reader, off, count, size, le) {
  const out = new Array(count);
  for (let i = 0; i < count; i++) out[i] = readSignedN(reader, off + i*size, size, le);
  return out;
}

function readUnsignedArray(reader, off, count, size, le) {
  const out = new Array(count);
  for (let i = 0; i < count; i++) out[i] = readUIntN(reader, off + i*size, size, le);
  return out;
}

function encodeUIntN(value, size, le) {
  const out = new Uint8Array(size);
  for (let i = 0; i < size; i++) {
    const shift = le ? 8*i : 8*(size-1-i);
    out[i] = (value >>> shift) & 0xff;
  }
  return out;
}

/* ------------------------------------------------------------------ */
/* Top-level convenience: extract from a File / ArrayBuffer            */
/* ------------------------------------------------------------------ */

/**
 * Extract kallsyms symbols from an Android boot.img OR a raw arm64
 * Image / vmlinux blob. Auto-detects the input type.
 *
 * @param {ArrayBuffer|Uint8Array} input
 * @param {object} opts
 *   - log(msg)
 *   - bitSize (32|64) override
 *   - useAbsolute (bool)
 *   - baseAddress (number|BigInt) override
 *
 * @returns {Promise<object>} result with:
 *   - versionString
 *   - versionNumber
 *   - architecture
 *   - baseAddress (BigInt)
 *   - offsets { tokenTable, tokenIndex, markers, names, numSyms, addresses }
 *   - symbolCount
 *   - symbols [{address: BigInt, type, name, isGlobal}]
 */
async function extractKallsymsFromImage(input, opts = {}) {
  const buf = input instanceof Uint8Array ? input : new Uint8Array(input);
  const log = opts.log || (() => {});
  log(`[+] Input size: ${buf.byteLength} bytes (0x${buf.byteLength.toString(16)})`);

  // 1. If this is an Android boot.img, pull out the kernel Image.
  const boot = parseAndroidBootImage(buf);
  let kernelImg = buf;
  if (boot) {
    log(`[+] Android boot.img: header v${boot.headerVer}, page_size=0x${boot.pageSize.toString(16)}, kernel_size=0x${boot.kernelSize.toString(16)}`);
    log(`[+] Kernel Image starts at file offset 0x${boot.kernelOffset.toString(16)}`);
    kernelImg = boot.image;
    log(`[+] Extracted kernel image: ${kernelImg.byteLength} bytes (0x${kernelImg.byteLength.toString(16)})`);
  } else {
    log('[+] Input is not a boot.img; treating as a raw kernel image.');
  }

  // 2. Run the finder.
  const finder = new KallsymsFinder(kernelImg, opts);
  finder.run();

  return {
    versionString:  finder.versionString,
    versionNumber:  finder.versionNumber,
    architecture:   finder.architecture,
    is64Bits:       finder.is64Bits,
    isBigEndian:    finder.isBigEndian,
    baseAddress:    finder.kernelTextCandidate,
    relativeBaseAddress: finder.relativeBaseAddress,
    hasBaseRelative: finder.hasBaseRelative,
    hasAbsolutePercpu: finder.hasAbsolutePercpu,
    offsets: {
      tokenTable: finder.kallsymsTokenTableOffset,
      tokenIndex: finder.kallsymsTokenIndexOffset,
      tokenIndexEnd: finder.kallsymsTokenIndexEndOffset,
      markers:   finder.kallsymsMarkersOffset,
      names:     finder.kallsymsNamesOffset,
      numSyms:   finder.kallsymsNumSymsOffset,
      addresses: finder.kallsymsAddressesOrOffsetsOffset,
    },
    symbolCount: finder.symbols.length,
    symbols:     finder.symbols,
  };
}

/* ------------------------------------------------------------------ */
/* Output formatter (mimics `nm` / `kallsyms_finder.py --output`)       */
/* ------------------------------------------------------------------ */

/**
 * Format the extracted symbols as `nm`-style text:
 *     ffffffc080000000 T _text
 *
 * @param {object} result from extractKallsymsFromImage
 * @param {object} fmt { sorted: true (default), width: 16|8 }
 */
function formatSymbolsLikeNm(result, fmt = {}) {
  const sorted = fmt.sorted !== false;
  const width = fmt.width || (result.is64Bits ? 16 : 8);
  const syms = sorted
    ? result.symbols.slice().sort((a, b) => a.address < b.address ? -1 : a.address > b.address ? 1 : 0)
    : result.symbols;
  const pad = '0'.repeat(width);
  return syms.map(s => {
    const hex = s.address.toString(16).padStart(width, '0');
    return `${hex} ${s.type} ${s.name}`;
  }).join('\n') + '\n';
}

/* ------------------------------------------------------------------ */
/* CommonJS + ESM dual export                                          */
/* ------------------------------------------------------------------ */

if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    extractKallsymsFromImage,
    formatSymbolsLikeNm,
    parseAndroidBootImage,
    KallsymsFinder,
    ByteReader,
  };
}
// ESM `import` consumers get the same names via these global exports.
if (typeof globalThis !== 'undefined') {
  globalThis.extractKallsymsFromImage = extractKallsymsFromImage;
  globalThis.formatSymbolsLikeNm = formatSymbolsLikeNm;
  globalThis.parseAndroidBootImage = parseAndroidBootImage;
}
