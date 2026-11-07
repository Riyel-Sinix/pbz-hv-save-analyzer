'use strict';
/*
 * Pure-JavaScript Oodle decompressor (subset) for pbz-tracker. Part of the portable core
 * (lib/core): Uint8Array in, Uint8Array out, no Node built-ins.
 *
 * Supports what Phantom Blade Zero save slots use: the Oodle LZ block/quantum framing,
 * the Mermaid/Selkie LZ decoder (ooz decoder type 10) and the shared "Kraken-style"
 * entropy layer (memcopy, Huffman with old and new code-length headers, RLE, tANS,
 * recursive and multi-array blocks). Other decoder types (Kraken 6, Leviathan 12,
 * LZNA 5, BitKnit 11) throw "unsupported decoder type N".
 *
 * PORTED FROM: ooz by Powzix, https://github.com/powzix/ooz (kraken.cpp)
 *   "Kraken Decompressor for Windows. Copyright (C) 2016, Powzix"
 *   LICENSE: GNU General Public License, version 3 or (at your option) any later version
 *   (GPL-3.0-or-later), as stated in the kraken.cpp header. The repository itself has no
 *   LICENSE file; the per-file header is the license grant. This JS port is a derivative
 *   work of that GPL-3.0 code.
 *
 * Deviations from ooz (none change the output for valid streams):
 *  - all reads/writes are bounds-checked; errors throw OodleError instead of returning -1;
 *  - per-quantum checksums (header flag) are skipped rather than verified (ooz leaves CRC
 *    unimplemented and would reject such streams);
 *  - a single-symbol Huffman table fills the output (ooz returns a bogus size there).
 */
const { OodleError, fail } = require('./entropy');
const { mermaidDecodeQuantum } = require('./mermaid');

const DECODER_NAMES = { 5: 'LZNA', 6: 'Kraken', 10: 'Mermaid/Selkie', 11: 'BitKnit', 12: 'Leviathan' };

function parseBlockHeader(src, p) {
  if (src.length - p < 2) fail('truncated block header');
  const b = src[p];
  if ((b & 0xF) !== 0xC || ((b >> 4) & 3) !== 0) fail(`invalid block header byte 0x${b.toString(16)}`);
  const b2 = src[p + 1];
  const type = b2 & 0x7F;
  return { restart: (b >> 7) & 1, uncompressed: (b >> 6) & 1, type, checksums: b2 >> 7 };
}

/**
 * Decompress an Oodle LZ stream.
 * @param {Uint8Array} src compressed bytes
 * @param {number} rawSize exact decompressed size
 * @returns {Uint8Array}
 */
function decompress(src, rawSize) {
  if (!(src instanceof Uint8Array)) throw new TypeError('decompress: src must be a Uint8Array');
  if (!Number.isSafeInteger(rawSize) || rawSize < 0) throw new RangeError(`decompress: bad rawSize ${rawSize}`);
  if (rawSize > 64 * 1024 * 1024) throw new OodleError(`rawSize ${rawSize} exceeds the 64 MiB limit`);
  const dst = new Uint8Array(rawSize);
  const sEnd = src.length;
  let s = 0, off = 0, hdr = null;
  while (off < rawSize) {
    let p = s;
    if ((off & 0x3FFFF) === 0) {
      hdr = parseBlockHeader(src, p);
      p += 2;
    }
    // Stored blocks of the 256 KiB-block family (Kraken 6, Mermaid 10, Leviathan 12) are just copied.
    const storedOk = hdr.uncompressed && (hdr.type === 6 || hdr.type === 10 || hdr.type === 12);
    if (hdr.type !== 10 && !storedOk) {
      const name = DECODER_NAMES[hdr.type];
      throw new OodleError(`unsupported decoder type ${hdr.type}${name ? ` (${name})` : ''}`);
    }
    const left = Math.min(0x40000, rawSize - off);

    if (hdr.uncompressed) {
      if (sEnd - p < left) fail('truncated input (stored block)');
      dst.set(src.subarray(p, p + left), off);
      s = p + left;
      off += left;
      continue;
    }

    // Quantum header
    if (sEnd - p < 3) fail('truncated quantum header');
    const v = (src[p] << 16) | (src[p + 1] << 8) | src[p + 2];
    const size = v & 0x3FFFF;
    let csize;
    if (size !== 0x3ffff) {
      csize = size + 1;
      p += hdr.checksums ? 6 : 3;
    } else if ((v >> 18) === 1) {
      if (sEnd - p < 4) fail('truncated quantum header');
      dst.fill(src[p + 3], off, off + left); // memset quantum
      s = p + 4;
      off += left;
      continue;
    } else {
      fail('invalid quantum header');
    }
    if (p > sEnd || sEnd - p < csize) fail('truncated input');
    if (csize > left) fail('quantum larger than its output');

    if (csize === left) {
      dst.set(src.subarray(p, p + left), off);
    } else {
      const n = mermaidDecodeQuantum(dst, off, off + left, src, p, p + csize);
      if (n !== csize) fail('quantum size mismatch');
    }
    s = p + csize;
    off += left;
  }
  if (s !== sEnd) fail(`trailing input: ${sEnd - s} byte(s) after ${rawSize} output bytes`);
  return dst;
}

module.exports = { decompress, OodleError };
