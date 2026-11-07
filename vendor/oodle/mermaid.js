'use strict';
// Mermaid / Selkie LZ decoder (ooz decoder type 10). Ported from ooz kraken.cpp
// (GPL-3.0-or-later, Copyright (C) 2016 Powzix); see index.js.
//
// Differences from ooz, all on the "reject bad input" side: every stream read and every
// match/literal copy is bounds-checked, and copies are done byte by byte (ooz uses 8-byte
// block copies, which give the same result because Mermaid match offsets are always >= 8).
const { decodeBytes, fail } = require('./entropy');

function decodeFarOffsets(src, s, end, count, offset) {
  const out = new Uint32Array(count);
  for (let i = 0; i < count; i++) {
    if (end - s < 3) fail('mermaid: truncated far offsets');
    let off = src[s] | (src[s + 1] << 8) | (src[s + 2] << 16);
    s += 3;
    if (offset >= 0xC00000 - 1 && off >= 0xc00000) {
      if (s === end) fail('mermaid: truncated far offsets');
      off += src[s++] * 0x400000;
    }
    if (off > offset) fail('mermaid: far offset out of range');
    out[i] = off;
  }
  return { offs: out, pos: s };
}

function readLzTable(mode, src, s, sEnd, dst, d, dstSize, offset) {
  if (mode > 1) fail(`mermaid: bad chunk mode ${mode}`);
  if (sEnd - s < 10) fail('mermaid: truncated lz table');
  if (offset === 0) {
    for (let i = 0; i < 8 && d + i < dst.length; i++) dst[d + i] = src[s + i];
    s += 8;
  }
  const lit = decodeBytes(src, s, sEnd, dstSize, null, 0);
  s += lit.used;
  const cmd = decodeBytes(src, s, sEnd, dstSize, null, 0);
  s += cmd.used;

  const cmd2OffsEnd = cmd.size;
  let cmd2Offs = cmd.size;
  if (dstSize > 0x10000) {
    if (sEnd - s < 2) fail('mermaid: truncated lz table');
    cmd2Offs = src[s] | (src[s + 1] << 8);
    s += 2;
    if (cmd2Offs > cmd2OffsEnd) fail('mermaid: bad command split');
  }

  if (sEnd - s < 2) fail('mermaid: truncated lz table');
  const off16Count = src[s] | (src[s + 1] << 8);
  let off16;
  if (off16Count === 0xffff) {
    s += 2;
    const hi = decodeBytes(src, s, sEnd, dstSize >> 1, null, 0);
    s += hi.used;
    const lo = decodeBytes(src, s, sEnd, dstSize >> 1, null, 0);
    s += lo.used;
    if (lo.size !== hi.size) fail('mermaid: off16 size mismatch');
    off16 = new Uint16Array(lo.size);
    for (let i = 0; i < lo.size; i++) off16[i] = lo.buf[lo.pos + i] + hi.buf[hi.pos + i] * 256;
  } else {
    s += 2;
    if (sEnd - s < off16Count * 2) fail('mermaid: truncated off16 stream');
    off16 = new Uint16Array(off16Count);
    for (let i = 0; i < off16Count; i++, s += 2) off16[i] = src[s] | (src[s + 1] << 8);
  }

  if (sEnd - s < 3) fail('mermaid: truncated lz table');
  const tmp = src[s] | (src[s + 1] << 8) | (src[s + 2] << 16);
  s += 3;
  let off32a = new Uint32Array(0), off32b = off32a;
  if (tmp !== 0) {
    let size1 = tmp >> 12, size2 = tmp & 0xFFF;
    if (size1 === 4095) {
      if (sEnd - s < 2) fail('mermaid: truncated lz table');
      size1 = src[s] | (src[s + 1] << 8);
      s += 2;
    }
    if (size2 === 4095) {
      if (sEnd - s < 2) fail('mermaid: truncated lz table');
      size2 = src[s] | (src[s + 1] << 8);
      s += 2;
    }
    let r = decodeFarOffsets(src, s, sEnd, size1, offset);
    off32a = r.offs; s = r.pos;
    r = decodeFarOffsets(src, s, sEnd, size2, offset + 0x10000);
    off32b = r.offs; s = r.pos;
  }
  return {
    lit: lit.buf, litPos: lit.pos, litEnd: lit.pos + lit.size,
    cmd: cmd.buf, cmdPos: cmd.pos, cmd2Offs, cmd2OffsEnd,
    off16, off16Pos: 0, off32a, off32b, lenPos: s, recent: -8,
  };
}

// Runs one 64 KiB half: commands cmd[cb..ce), output dst[dBegin + startoff .. dBegin + dSize).
function runLz(mode, dst, dBegin, dSize, startoff, src, sEnd, lz, cmd, cb, ce, off32) {
  const dEnd = dBegin + dSize;
  let d = dBegin + startoff;
  let recent = lz.recent, lp = lz.litPos, o16p = lz.off16Pos, lenp = lz.lenPos, o32p = 0;
  const lit = lz.lit, litEnd = lz.litEnd, off16 = lz.off16, o16n = off16.length, o32n = off32.length;
  const add = mode === 0;
  let length, m;

  const readLength = () => {
    if (sEnd - lenp === 0) fail('mermaid: length stream exhausted');
    let len = src[lenp];
    if (len > 251) {
      if (sEnd - lenp < 3) fail('mermaid: length stream exhausted');
      len += (src[lenp + 1] | (src[lenp + 2] << 8)) * 4;
      lenp += 2;
    }
    lenp += 1;
    return len;
  };
  const copyLits = (n) => {
    if (litEnd - lp < n || dEnd - d < n) fail('mermaid: literal overrun');
    if (add) {
      if (d + recent < 0) fail('mermaid: offset before start');
      for (let i = 0; i < n; i++) dst[d + i] = lit[lp + i] + dst[d + i + recent];
    } else if (n > 32) {
      dst.set(lit.subarray(lp, lp + n), d);
    } else {
      for (let i = 0; i < n; i++) dst[d + i] = lit[lp + i];
    }
    d += n; lp += n;
  };
  const copyMatch = (n) => {
    if (m < 0) fail('mermaid: offset before start');
    if (dEnd - d < n) fail('mermaid: match overrun');
    if (d - m >= n && n > 32) {
      dst.copyWithin(d, m, m + n);
      d += n;
    } else {
      for (let i = 0; i < n; i++) dst[d++] = dst[m++];
    }
  };

  while (cb < ce) {
    const c = cmd[cb++];
    if (c >= 24) {
      copyLits(c & 7);
      if (!(c & 0x80)) {
        if (o16p >= o16n) fail('mermaid: off16 stream exhausted');
        recent = -off16[o16p++];
      }
      m = d + recent;
      copyMatch((c >> 3) & 0xF);
    } else if (c > 2) {
      if (o32p >= o32n) fail('mermaid: off32 stream exhausted');
      m = dBegin - off32[o32p++];
      recent = m - d;
      copyMatch(c + 5);
    } else if (c === 0) {
      copyLits(readLength() + 64);
    } else if (c === 1) {
      length = readLength() + 91;
      if (o16p >= o16n) fail('mermaid: off16 stream exhausted');
      m = d - off16[o16p++];
      recent = m - d;
      copyMatch(length);
    } else {
      length = readLength() + 29;
      if (o32p >= o32n) fail('mermaid: off32 stream exhausted');
      m = dBegin - off32[o32p++];
      recent = m - d;
      copyMatch(length);
    }
  }
  if (dEnd - d > 0) copyLits(dEnd - d);

  lz.recent = recent; lz.litPos = lp; lz.off16Pos = o16p; lz.lenPos = lenp;
}

function processLzRuns(mode, src, sEnd, dst, d, dstSize, offset, lz) {
  for (let it = 0; it < 2; it++) {
    const cur = Math.min(dstSize, 0x10000);
    const startoff = offset === 0 && it === 0 ? 8 : 0;
    if (startoff > cur) fail('mermaid: chunk too small');
    if (it === 0) {
      runLz(mode, dst, d, cur, startoff, src, sEnd, lz, lz.cmd, lz.cmdPos, lz.cmdPos + lz.cmd2Offs, lz.off32a);
    } else {
      runLz(mode, dst, d, cur, startoff, src, sEnd, lz, lz.cmd, lz.cmdPos + lz.cmd2Offs, lz.cmdPos + lz.cmd2OffsEnd, lz.off32b);
    }
    d += cur;
    dstSize -= cur;
    if (dstSize === 0) break;
  }
  if (lz.lenPos !== sEnd) fail('mermaid: trailing data in chunk');
}

// Decodes one quantum into dst[d .. dEnd) from src[s .. sEnd). Returns source bytes used.
function mermaidDecodeQuantum(dst, d, dEnd, src, s, sEnd) {
  const sIn = s;
  while (dEnd - d !== 0) {
    const dstCount = Math.min(dEnd - d, 0x20000);
    if (sEnd - s < 4) fail('mermaid: truncated chunk');
    const hdr = (src[s] << 16) | (src[s + 1] << 8) | src[s + 2];
    let used;
    if (!(hdr & 0x800000)) {
      const r = decodeBytes(src, s, sEnd, dstCount, dst, d);
      if (r.size !== dstCount) fail('mermaid: entropy-only chunk size mismatch');
      used = r.used;
    } else {
      s += 3;
      used = hdr & 0x7FFFF;
      const mode = (hdr >> 19) & 0xF;
      if (sEnd - s < used) fail('mermaid: truncated chunk');
      if (used < dstCount) {
        const lz = readLzTable(mode, src, s, s + used, dst, d, dstCount, d);
        processLzRuns(mode, src, s + used, dst, d, dstCount, d, lz);
      } else if (used > dstCount || mode !== 0) {
        fail('mermaid: bad stored chunk');
      } else {
        dst.set(src.subarray(s, s + dstCount), d);
      }
    }
    s += used;
    d += dstCount;
  }
  return s - sIn;
}

module.exports = { mermaidDecodeQuantum };
