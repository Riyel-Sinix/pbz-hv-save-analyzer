'use strict';
// Oodle "Kraken-style" entropy layer (DecodeBytes): memcopy, Huffman (old and new code-length
// headers, 3-stream and 6-stream), RLE, tANS, recursive and multi-array blocks.
// Ported from ooz kraken.cpp (GPL-3.0-or-later, Copyright (C) 2016 Powzix); see index.js.
// Every function throws OodleError on bad input instead of returning -1.

class OodleError extends Error {
  constructor(msg) { super(`Oodle: ${msg}`); this.name = 'OodleError'; }
}
const fail = (msg) => { throw new OodleError(msg); };

// Big scratch-size cap used where ooz bounds an output by its scratch buffer.
const SCRATCH_CAP = 0x6C000;

// ---------------------------------------------------------------------------
// BitReader (MSB-first, ooz semantics: |bitpos| is where the next byte lands).
class BitReader {
  constructor(buf, p, pEnd) {
    this.buf = buf; this.p = p; this.pEnd = pEnd; this.bits = 0; this.bitpos = 24;
  }
  refill() {
    const buf = this.buf;
    while (this.bitpos > 0) {
      const b = this.p < this.pEnd ? buf[this.p] : 0;
      this.bits = (this.bits | (b << this.bitpos)) >>> 0;
      this.bitpos -= 8;
      this.p++;
    }
  }
  readBitNoRefill() {
    const r = this.bits >>> 31;
    this.bits = (this.bits << 1) >>> 0;
    this.bitpos += 1;
    return r;
  }
  readBit() { this.refill(); return this.readBitNoRefill(); }
  // 1 <= n <= 31
  readBitsNoRefill(n) {
    const r = this.bits >>> (32 - n);
    this.bits = (this.bits << n) >>> 0;
    this.bitpos += n;
    return r;
  }
  // 0 <= n <= 31
  readBitsNoRefillZero(n) {
    const r = (this.bits >>> 1) >>> (31 - n);
    this.bits = (this.bits << n) >>> 0;
    this.bitpos += n;
    return r;
  }
}

const bsr = (x) => 31 - Math.clz32(x);
const bsf = (x) => 31 - Math.clz32(x & -x);

// ---------------------------------------------------------------------------
// Huffman code lengths

function huffReadCodeLengthsOld(br, syms, codePrefix) {
  if (br.readBitNoRefill()) {
    let sym = 0, numSymbols = 0, avg = 32, n;
    const forced = br.readBitsNoRefill(2);
    const thres = (1 << (31 - (20 >>> forced))) >>> 0;
    let skipZeros = br.readBit();
    for (;;) {
      if (!skipZeros) {
        // run of zeros
        if (!(br.bits & 0xff000000)) return -1;
        sym += br.readBitsNoRefill(2 * (Math.clz32(br.bits) + 1)) - 2 + 1;
        if (sym >= 256) break;
      }
      skipZeros = 0;
      br.refill();
      if (!(br.bits & 0xff000000)) return -1;
      n = br.readBitsNoRefill(2 * (Math.clz32(br.bits) + 1)) - 2 + 1;
      if (sym + n > 256) return -1;
      br.refill();
      numSymbols += n;
      do {
        if (br.bits < thres) return -1;
        const lz = Math.clz32(br.bits);
        const v = br.readBitsNoRefill(lz + forced + 1) + ((lz - 1) << forced);
        const codelen = (-(v & 1) ^ (v >> 1)) + ((avg + 2) >> 2);
        if (codelen < 1 || codelen > 11) return -1;
        avg = codelen + ((3 * avg + 2) >> 2);
        br.refill();
        syms[codePrefix[codelen]++] = sym++;
      } while (--n);
      if (sym === 256) break;
    }
    return (sym === 256 && numSymbols >= 2) ? numSymbols : -1;
  }
  // sparse symbol encoding
  const numSymbols = br.readBitsNoRefill(8);
  if (numSymbols === 0) return -1;
  if (numSymbols === 1) {
    syms[0] = br.readBitsNoRefill(8);
  } else {
    const codelenBits = br.readBitsNoRefill(3);
    if (codelenBits > 4) return -1;
    for (let i = 0; i < numSymbols; i++) {
      br.refill();
      const sym = br.readBitsNoRefill(8);
      const codelen = br.readBitsNoRefillZero(codelenBits) + 1;
      if (codelen > 11) return -1;
      syms[codePrefix[codelen]++] = sym;
    }
  }
  return numSymbols;
}

function readFluff(br, numSymbols) {
  if (numSymbols === 256) return 0;
  let x = 257 - numSymbols;
  if (x > numSymbols) x = numSymbols;
  x *= 2;
  const y = bsr(x - 1) + 1;
  const v = br.bits >>> (32 - y);
  const z = (1 << y) - x;
  if ((v >>> 1) >= z) {
    br.bits = (br.bits << y) >>> 0;
    br.bitpos += y;
    return v - z;
  }
  br.bits = (br.bits << (y - 1)) >>> 0;
  br.bitpos += y - 1;
  return v >>> 1;
}

// BitReader2: plain MSB-first bit cursor { p, pEnd, bitpos } over |buf|.
function toBitReader2(br) {
  return { p: br.p - ((24 - br.bitpos + 7) >>> 3), pEnd: br.pEnd, bitpos: (br.bitpos - 24) & 7 };
}
function fromBitReader2(br, br2) {
  br.bitpos = 24;
  br.p = br2.p;
  br.bits = 0;
  br.refill();
  br.bits = (br.bits << br2.bitpos) >>> 0;
  br.bitpos += br2.bitpos;
}

// Unary (Rice) values: number of 0-bits before each 1-bit, MSB first.
function decodeGolombRiceLengths(buf, dst, size, br2) {
  let p = br2.p;
  const pEnd = br2.pEnd;
  if (p >= pEnd) return false;
  let bit = br2.bitpos, cur = buf[p], count = 0, i = 0;
  while (i < size) {
    if (bit === 8) {
      p++;
      if (p >= pEnd) return false;
      cur = buf[p];
      bit = 0;
      if (cur === 0) { count += 8; bit = 8; continue; }
    }
    if ((cur >> (7 - bit)) & 1) { dst[i++] = count & 0xFF; count = 0; } else count++;
    bit++;
  }
  if (bit === 8) { p++; bit = 0; }
  br2.p = p;
  br2.bitpos = bit;
  return true;
}

// Appends |bitcount| raw bits (MSB first) to each of the first |size| values.
function decodeGolombRiceBits(buf, dst, size, bitcount, br2) {
  if (bitcount === 0) return true;
  const bitsRequired = br2.bitpos + bitcount * size;
  const bytesRequired = (bitsRequired + 7) >>> 3;
  if (bytesRequired > br2.pEnd - br2.p) return false;
  let bp = br2.p * 8 + br2.bitpos;
  for (let i = 0; i < size; i++) {
    let v = 0;
    for (let k = 0; k < bitcount; k++, bp++) v = (v << 1) | ((buf[bp >>> 3] >> (7 - (bp & 7))) & 1);
    dst[i] = ((dst[i] << bitcount) + v) & 0xFF;
  }
  br2.p += bitsRequired >>> 3;
  br2.bitpos = bitsRequired & 7;
  return true;
}

// Returns number of ranges (pushed as [symbol, num] into |ranges|), or -1.
function huffConvertToRanges(ranges, numSymbols, P, symlen, sl, br) {
  const numRanges = P >> 1;
  let v, symIdx = 0;
  if (P & 1) {
    br.refill();
    v = symlen[sl++];
    if (v >= 8) return -1;
    symIdx = br.readBitsNoRefill(v + 1) + (1 << (v + 1)) - 1;
  }
  let symsUsed = 0;
  for (let i = 0; i < numRanges; i++) {
    br.refill();
    v = symlen[sl];
    if (v >= 9) return -1;
    const num = br.readBitsNoRefillZero(v) + (1 << v);
    v = symlen[sl + 1];
    if (v >= 8) return -1;
    const space = br.readBitsNoRefill(v + 1) + (1 << (v + 1)) - 1;
    ranges.push([symIdx, num]);
    symsUsed += num;
    symIdx += num + space;
    sl += 2;
  }
  if (symIdx >= 256 || symsUsed >= numSymbols || symIdx + numSymbols - symsUsed > 256) return -1;
  ranges.push([symIdx, numSymbols - symsUsed]);
  return ranges.length;
}

function huffReadCodeLengthsNew(br, syms, codePrefix) {
  const forced = br.readBitsNoRefill(2);
  const numSymbols = br.readBitsNoRefill(8) + 1;
  const fluff = readFluff(br, numSymbols);
  const codeLen = new Uint8Array(512 + 16);
  const br2 = toBitReader2(br);
  if (!decodeGolombRiceLengths(br.buf, codeLen, numSymbols + fluff, br2)) return -1;
  if (!decodeGolombRiceBits(br.buf, codeLen, numSymbols, forced, br2)) return -1;
  fromBitReader2(br, br2);

  let runningSum = 0x1e;
  for (let i = 0; i < numSymbols; i++) {
    let v = codeLen[i];
    v = -(v & 1) ^ (v >> 1);
    const cl = (v + (runningSum >>> 2) + 1) & 0xFF;
    if (cl < 1 || cl > 11) return -1;
    codeLen[i] = cl;
    runningSum = (runningSum + v) >>> 0;
  }

  const ranges = [];
  const n = huffConvertToRanges(ranges, numSymbols, fluff, codeLen, numSymbols, br);
  if (n <= 0) return -1;
  let cp = 0;
  for (let i = 0; i < n; i++) {
    let sym = ranges[i][0], num = ranges[i][1];
    do { syms[codePrefix[codeLen[cp++]]++] = sym++; } while (--num);
  }
  return numSymbols;
}

// 11-bit index reversal table (MSB-first canonical LUT -> LSB-first reading LUT).
const REV11 = (() => {
  const t = new Uint16Array(2048);
  for (let i = 0; i < 2048; i++) {
    let r = 0;
    for (let b = 0; b < 11; b++) if (i & (1 << b)) r |= 1 << (10 - b);
    t[i] = r;
  }
  return t;
})();

const CODE_PREFIX_ORG = [0x0, 0x0, 0x2, 0x6, 0xE, 0x1E, 0x3E, 0x7E, 0xFE, 0x1FE, 0x2FE, 0x3FE];

function huffMakeRevLut(prefixCur, syms) {
  const len = new Uint8Array(2048), sym = new Uint8Array(2048);
  let cur = 0;
  for (let i = 1; i < 11; i++) {
    const start = CODE_PREFIX_ORG[i];
    const count = prefixCur[i] - start;
    if (count) {
      const step = 1 << (11 - i);
      const num = count << (11 - i);
      if (cur + num > 2048) return null;
      len.fill(i, cur, cur + num);
      for (let j = 0; j < count; j++) sym.fill(syms[start + j], cur + j * step, cur + (j + 1) * step);
      cur += num;
    }
  }
  const count11 = prefixCur[11] - CODE_PREFIX_ORG[11];
  if (count11) {
    if (cur + count11 > 2048) return null;
    len.fill(11, cur, cur + count11);
    for (let j = 0; j < count11; j++) sym[cur + j] = syms[CODE_PREFIX_ORG[11] + j];
    cur += count11;
  }
  if (cur !== 2048) return null;
  const rlen = new Uint8Array(2048), rsym = new Uint8Array(2048);
  for (let i = 0; i < 2048; i++) { rlen[i] = len[REV11[i]]; rsym[i] = sym[REV11[i]]; }
  return { len: rlen, sym: rsym };
}

// Three interleaved LSB-first streams: forward from |s|, backward from |e|, forward from |mid|.
// Consumption must end exactly at |mid| for the first and meet in the middle for the other two.
function huffDecodeCore(src, s, mid, e, out, o, oEnd, lut) {
  if (s > mid || mid > e) fail('huffman: bad stream split');
  const lenT = lut.len, symT = lut.sym;
  let p1 = s, a1 = 0, c1 = 0;
  let p2 = e, a2 = 0, c2 = 0;
  let p3 = mid, a3 = 0, c3 = 0;
  let k, n;
  while (o < oEnd) {
    while (c1 < 11) { a1 |= (p1 < e ? src[p1] : 0) << c1; p1++; c1 += 8; }
    k = a1 & 0x7FF; n = lenT[k]; out[o++] = symT[k]; a1 >>>= n; c1 -= n;
    if (o >= oEnd) break;
    while (c2 < 11) { p2--; a2 |= (p2 >= s ? src[p2] : 0) << c2; c2 += 8; }
    k = a2 & 0x7FF; n = lenT[k]; out[o++] = symT[k]; a2 >>>= n; c2 -= n;
    if (o >= oEnd) break;
    while (c3 < 11) { a3 |= (p3 < e ? src[p3] : 0) << c3; p3++; c3 += 8; }
    k = a3 & 0x7FF; n = lenT[k]; out[o++] = symT[k]; a3 >>>= n; c3 -= n;
  }
  const end1 = p1 - (c1 >> 3), end2 = p2 + (c2 >> 3), end3 = p3 - (c3 >> 3);
  if (end1 !== mid || end3 !== end2) fail('huffman: stream length mismatch');
}

function decodeHuff(src, pos, srcSize, out, o, outSize, type) {
  const srcEnd = pos + srcSize;
  const br = new BitReader(src, pos, srcEnd);
  br.refill();
  const codePrefix = Uint32Array.from(CODE_PREFIX_ORG);
  const syms = new Uint8Array(1280);
  let numSyms;
  if (!br.readBitNoRefill()) numSyms = huffReadCodeLengthsOld(br, syms, codePrefix);
  else if (!br.readBitNoRefill()) numSyms = huffReadCodeLengthsNew(br, syms, codePrefix);
  else fail('huffman: unknown code-length format');
  if (numSyms < 1) fail('huffman: bad code lengths');
  let s = br.p - Math.trunc((24 - br.bitpos) / 8);
  if (numSyms === 1) { out.fill(syms[0], o, o + outSize); return srcSize; }
  const lut = huffMakeRevLut(codePrefix, syms);
  if (!lut) fail('huffman: incomplete code');
  if (type === 1) {
    if (s + 3 > srcEnd) fail('huffman: truncated');
    const splitMid = src[s] | (src[s + 1] << 8);
    s += 2;
    huffDecodeCore(src, s, s + splitMid, srcEnd, out, o, o + outSize, lut);
  } else {
    if (s + 6 > srcEnd) fail('huffman: truncated');
    const half = (outSize + 1) >> 1;
    const splitMid = src[s] | (src[s + 1] << 8) | (src[s + 2] << 16);
    s += 3;
    if (splitMid > srcEnd - s) fail('huffman: bad split');
    const mid = s + splitMid;
    const splitLeft = src[s] | (src[s + 1] << 8);
    s += 2;
    if (mid - s < splitLeft + 2 || srcEnd - mid < 3) fail('huffman: bad split');
    const splitRight = src[mid] | (src[mid + 1] << 8);
    if (srcEnd - (mid + 2) < splitRight + 2) fail('huffman: bad split');
    huffDecodeCore(src, s, s + splitLeft, mid, out, o, o + half, lut);
    huffDecodeCore(src, mid + 2, mid + 2 + splitRight, srcEnd, out, o + half, o + outSize, lut);
  }
  return srcSize;
}

// ---------------------------------------------------------------------------
// RLE

function decodeRle(src, pos, srcSize, dst, d, dstSize) {
  if (srcSize <= 1) {
    if (srcSize !== 1) fail('rle: empty');
    dst.fill(src[pos], d, d + dstSize);
    return 1;
  }
  const dEnd = d + dstSize;
  let cmd, cp, ce;
  if (src[pos]) {
    const r = decodeBytes(src, pos, pos + srcSize, SCRATCH_CAP, null, 0);
    if (r.used <= 0) fail('rle: bad command prefix');
    const cmdLen = srcSize - r.used + r.size;
    cmd = new Uint8Array(cmdLen);
    cmd.set(r.buf.subarray(r.pos, r.pos + r.size), 0);
    cmd.set(src.subarray(pos + r.used, pos + srcSize), r.size);
    cp = 0; ce = cmdLen;
  } else {
    cmd = src; cp = pos + 1; ce = pos + srcSize;
  }
  let rleByte = 0;
  while (cp < ce) {
    const c = cmd[ce - 1];
    if (c === 0 || c - 1 >= 0x2f) {
      ce--;
      const copy = (-1 - c) & 0xF, rle = c >> 4;
      if (dEnd - d < copy + rle || ce - cp < copy) fail('rle: overflow');
      dst.set(cmd.subarray(cp, cp + copy), d);
      cp += copy; d += copy;
      dst.fill(rleByte, d, d + rle); d += rle;
    } else if (c === 1) {
      rleByte = cmd[cp++];
      ce--;
    } else {
      if (ce - 2 < cp) fail('rle: truncated command');
      const w = cmd[ce - 2] | (cmd[ce - 1] << 8);
      ce -= 2;
      if (c >= 0x10) {
        const data = (w - 4096) >>> 0;
        const copy = data & 0x3F, rle = data >>> 6;
        if (dEnd - d < copy + rle || ce - cp < copy) fail('rle: overflow');
        dst.set(cmd.subarray(cp, cp + copy), d);
        cp += copy; d += copy;
        dst.fill(rleByte, d, d + rle); d += rle;
      } else if (c >= 9) {
        const rle = Math.imul(w - 0x8ff, 128) >>> 0;
        if (dEnd - d < rle) fail('rle: overflow');
        dst.fill(rleByte, d, d + rle); d += rle;
      } else {
        const copy = Math.imul(w - 511, 64) >>> 0;
        if (ce - cp < copy || dEnd - d < copy) fail('rle: overflow');
        dst.set(cmd.subarray(cp, cp + copy), d);
        d += copy; cp += copy;
      }
    }
  }
  if (ce !== cp || d !== dEnd) fail('rle: size mismatch');
  return srcSize;
}

// ---------------------------------------------------------------------------
// tANS

function tansDecodeTable(br, Lbits) {
  br.refill();
  const A = [], B = [];
  const L = 1 << Lbits;
  if (br.readBitNoRefill()) {
    const Q = br.readBitsNoRefill(3);
    const numSymbols = br.readBitsNoRefill(8) + 1;
    if (numSymbols < 2) return null;
    const fluff = readFluff(br, numSymbols);
    const total = fluff + numSymbols;
    const rice = new Uint8Array(512 + 16);
    const br2 = toBitReader2(br);
    if (!decodeGolombRiceLengths(br.buf, rice, total, br2)) return null;
    fromBitReader2(br, br2);
    const ranges = [];
    const nr = huffConvertToRanges(ranges, numSymbols, fluff, rice, numSymbols, br);
    if (nr < 0) return null;
    br.refill();
    let ri = 0, average = 6, somesum = 0;
    for (let r = 0; r < nr; r++) {
      let symbol = ranges[r][0], num = ranges[r][1];
      do {
        br.refill();
        const nextra = Q + rice[ri++];
        if (nextra > 15) return null;
        let v = br.readBitsNoRefillZero(nextra) + (1 << nextra) - (1 << Q);
        const ad4 = average >> 2;
        let limit = 2 * ad4;
        if (v <= limit) v = ad4 + (-(v & 1) ^ (v >>> 1));
        if (limit > v) limit = v;
        v += 1;
        average += limit - ad4;
        if (v === 1) A.push(symbol);
        else if (v >= 2) B.push((symbol << 16) + v);
        somesum += v;
        symbol += 1;
      } while (--num);
    }
    if (somesum !== L) return null;
    return { A, B };
  }
  const seen = new Uint8Array(256);
  let count = br.readBitsNoRefill(3) + 1;
  const bitsPerSym = bsr(Lbits) + 1;
  const maxDeltaBits = br.readBitsNoRefill(bitsPerSym);
  if (maxDeltaBits === 0 || maxDeltaBits > Lbits) return null;
  let weight = 0, totalWeights = 0;
  do {
    br.refill();
    const sym = br.readBitsNoRefill(8);
    if (seen[sym]) return null;
    const delta = br.readBitsNoRefill(maxDeltaBits);
    weight += delta;
    if (weight === 0) return null;
    seen[sym] = 1;
    if (weight === 1) A.push(sym); else B.push((sym << 16) + weight);
    totalWeights += weight;
  } while (--count);
  br.refill();
  const sym = br.readBitsNoRefill(8);
  if (seen[sym]) return null;
  const rem = (L - totalWeights) >>> 0;
  if (rem < weight || rem <= 1) return null;
  B.push((sym << 16) + rem);
  A.sort((x, y) => x - y);
  B.sort((x, y) => x - y);
  return { A, B };
}

function tansInitLut(td, Lbits) {
  const L = 1 << Lbits;
  const lx = new Uint32Array(L), lb = new Uint8Array(L), ls = new Uint8Array(L), lw = new Uint16Array(L);
  const aUsed = td.A.length;
  const slotsLeft = L - aUsed;
  const sa = slotsLeft >>> 2, rem = slotsLeft & 3;
  const ptr = [0, 0, 0, 0];
  let sb = sa + (rem > 0 ? 1 : 0); ptr[1] = sb;
  sb += sa + (rem > 1 ? 1 : 0); ptr[2] = sb;
  sb += sa + (rem > 2 ? 1 : 0); ptr[3] = sb;
  for (let i = 0; i < aUsed; i++) {
    const k = slotsLeft + i;
    lw[k] = 0; lb[k] = Lbits; lx[k] = L - 1; ls[k] = td.A[i];
  }
  let weightsSum = 0;
  for (const bv of td.B) {
    const weight = bv & 0xffff, symbol = bv >>> 16;
    if (weight > 4) {
      const symBits = bsr(weight);
      let Z = Lbits - symBits;
      let leBx = Z, leX = (1 << Z) - 1, leW = (L - 1) & (weight << Z);
      let add = 1 << Z;
      let X = (1 << (symBits + 1)) - weight;
      for (let j = 0; j < 4; j++) {
        let d = ptr[j];
        const Y = (weight + ((weightsSum - j - 1) & 3)) >> 2;
        if (X >= Y) {
          for (let n = Y; n; n--) { ls[d] = symbol; lb[d] = leBx; lx[d] = leX; lw[d] = leW; d++; leW = (leW + add) & 0xFFFF; }
          X -= Y;
        } else {
          for (let n = X; n; n--) { ls[d] = symbol; lb[d] = leBx; lx[d] = leX; lw[d] = leW; d++; leW = (leW + add) & 0xFFFF; }
          Z--;
          add >>= 1;
          leBx = Z; leW = 0; leX >>>= 1;
          for (let n = Y - X; n; n--) { ls[d] = symbol; lb[d] = leBx; lx[d] = leX; lw[d] = leW; d++; leW = (leW + add) & 0xFFFF; }
          X = weight;
        }
        ptr[j] = d;
      }
    } else {
      let bits = ((1 << weight) - 1) << (weightsSum & 3);
      bits |= bits >> 4;
      let n = weight, ww = weight;
      do {
        const idx = bsf(bits);
        bits &= bits - 1;
        const d = ptr[idx]++;
        const wb = bsr(ww);
        ls[d] = symbol;
        lb[d] = Lbits - wb;
        lx[d] = (1 << (Lbits - wb)) - 1;
        lw[d] = (L - 1) & (ww++ << (Lbits - wb));
      } while (--n);
    }
    weightsSum += weight;
  }
  return { lx, lb, ls, lw, L };
}

function decodeTans(src, pos, srcSize, out, o, outSize) {
  if (srcSize < 8 || outSize < 5) fail('tans: too small');
  const regionEnd = pos + srcSize;
  let srcEnd = regionEnd;
  const br = new BitReader(src, pos, srcEnd);
  br.refill();
  if (br.readBitNoRefill()) fail('tans: reserved bit set');
  const Lbits = br.readBitsNoRefill(2) + 8;
  const td = tansDecodeTable(br, Lbits);
  if (!td) fail('tans: bad table');
  let s = br.p - Math.trunc((24 - br.bitpos) / 8);
  if (s >= srcEnd) fail('tans: truncated');
  const { lx, lb, ls, lw, L } = tansInitLut(td, Lbits);

  const rd = (i) => (i >= pos && i < regionEnd ? src[i] : 0);
  const le32 = (i) => (rd(i) | (rd(i + 1) << 8) | (rd(i + 2) << 16) | (rd(i + 3) << 24)) >>> 0;
  // _byteswap_ulong(*(uint32*)(p - 4)): the byte at p-1 becomes the low byte.
  const rev32 = (p) => (rd(p - 1) | (rd(p - 2) << 8) | (rd(p - 3) << 16) | (rd(p - 4) << 24)) >>> 0;

  const Lmask = L - 1;
  let bitsF = le32(s); s += 4;
  let bitsB = rev32(srcEnd); srcEnd -= 4;
  let bitposF = 32, bitposB = 32;
  const st = new Uint32Array(5);
  st[0] = bitsF & Lmask; st[1] = bitsB & Lmask;
  bitsF >>>= Lbits; bitposF -= Lbits; bitsB >>>= Lbits; bitposB -= Lbits;
  st[2] = bitsF & Lmask; st[3] = bitsB & Lmask;
  bitsF >>>= Lbits; bitposF -= Lbits; bitsB >>>= Lbits; bitposB -= Lbits;
  bitsF = (bitsF | (le32(s) << bitposF)) >>> 0;
  s += (31 - bitposF) >> 3;
  bitposF |= 24;
  st[4] = bitsF & Lmask;
  bitsF >>>= Lbits; bitposF -= Lbits;

  let ptrF = s - (bitposF >> 3); bitposF &= 7;
  let ptrB = srcEnd + (bitposB >> 3); bitposB &= 7;

  const oEnd = o + outSize - 5;
  if (ptrF > ptrB) fail('tans: bad stream');
  // One loop = 5 forward rounds (states 0..4) then 5 backward rounds, refilling before 0, 2, 4.
  if (o < oEnd) {
    outer: for (;;) {
      for (let step = 0; step < 10; step++) {
        const fwd = step < 5;
        const si = fwd ? step : step - 5;
        if (si === 0 || si === 2 || si === 4) {
          if (fwd) {
            bitsF = (bitsF | (le32(ptrF) << bitposF)) >>> 0;
            ptrF += (31 - bitposF) >> 3;
            bitposF |= 24;
          } else {
            bitsB = (bitsB | (rev32(ptrB) << bitposB)) >>> 0;
            ptrB -= (31 - bitposB) >> 3;
            bitposB |= 24;
          }
        }
        const e = st[si];
        if (e >= L) fail('tans: bad state');
        out[o++] = ls[e];
        const bx = lb[e];
        if (fwd) {
          bitposF -= bx;
          st[si] = (bitsF & lx[e]) + lw[e];
          bitsF >>>= bx;
        } else {
          bitposB -= bx;
          st[si] = (bitsB & lx[e]) + lw[e];
          bitsB >>>= bx;
        }
        if (o >= oEnd) break outer;
      }
    }
  }
  if (ptrB - ptrF + (bitposF >> 3) + (bitposB >> 3) !== 0) fail('tans: stream length mismatch');
  if ((st[0] | st[1] | st[2] | st[3] | st[4]) & ~0xFF) fail('tans: bad final state');
  for (let i = 0; i < 5; i++) out[oEnd + i] = st[i];
  return srcSize;
}

// ---------------------------------------------------------------------------
// Block sizes, recursive and multi-array

function getBlockSize(src, pos, end, destCapacity) {
  if (end - pos < 2) return -1;
  const b0 = src[pos];
  const type = (b0 >> 4) & 7;
  if (type === 0) {
    let size, p;
    if (b0 >= 0x80) { size = ((b0 << 8) | src[pos + 1]) & 0xFFF; p = pos + 2; } else {
      if (end - pos < 3) return -1;
      size = (b0 << 16) | (src[pos + 1] << 8) | src[pos + 2];
      if (size & ~0x3ffff) return -1;
      p = pos + 3;
    }
    if (size > destCapacity || end - p < size) return -1;
    return { used: p + size - pos, size };
  }
  if (type >= 6) return -1;
  let srcSize, dstSize, p;
  if (b0 >= 0x80) {
    if (end - pos < 3) return -1;
    const bits = (b0 << 16) | (src[pos + 1] << 8) | src[pos + 2];
    srcSize = bits & 0x3ff;
    dstSize = srcSize + ((bits >> 10) & 0x3ff) + 1;
    p = pos + 3;
  } else {
    if (end - pos < 5) return -1;
    const bits = ((src[pos + 1] << 24) | (src[pos + 2] << 16) | (src[pos + 3] << 8) | src[pos + 4]) >>> 0;
    srcSize = bits & 0x3ffff;
    dstSize = (((bits >>> 18) | (b0 << 14)) & 0x3FFFF) + 1;
    if (srcSize >= dstSize) return -1;
    p = pos + 5;
  }
  if (end - p < srcSize || dstSize > destCapacity) return -1;
  return { used: srcSize, size: dstSize };
}

const BITMASKS = new Uint32Array(32);
for (let i = 0; i < 32; i++) BITMASKS[i] = i === 31 ? 0xffffffff : ((2 ** (i + 1)) - 1);
const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;

// Only array_count == 1 is used (from the recursive decoder). Output is written contiguously at dst[d..].
function decodeMultiArray(src, pos, end, dst, d, dEnd, arrayCount) {
  const org = pos;
  if (end - pos < 4) fail('multiarray: truncated');
  let nArr = src[pos++];
  if (!(nArr & 0x80)) fail('multiarray: bad header');
  nArr &= 0x3f;
  const d0 = d;
  if (nArr === 0) {
    for (let i = 0; i < arrayCount; i++) {
      const r = decodeBytes(src, pos, end, dEnd - d, dst, d);
      d += r.size;
      pos += r.used;
    }
    return { used: pos - org, size: d - d0 };
  }
  const ent = [];
  let total = 0;
  for (let i = 0; i < nArr; i++) {
    const r = decodeBytes(src, pos, end, SCRATCH_CAP, null, 0);
    ent.push({ buf: r.buf, p: r.pos, size: r.size });
    total += r.size;
    pos += r.used;
  }
  if (end - pos < 3) fail('multiarray: truncated');
  const Q = src[pos] | (src[pos + 1] << 8);
  pos += 2;
  const bs = getBlockSize(src, pos, end, total);
  if (bs === -1) fail('multiarray: bad index block');
  const numIndexes = bs.size;
  let numLens = numIndexes - arrayCount;
  if (numLens < 1) fail('multiarray: bad index count');
  let lenlog2, idxs;
  if (Q & 0x8000) {
    const r = decodeBytes(src, pos, end, numIndexes, null, 0);
    if (r.size !== numIndexes) fail('multiarray: index size mismatch');
    pos += r.used;
    lenlog2 = new Uint8Array(numIndexes);
    idxs = new Uint8Array(numIndexes);
    for (let i = 0; i < numIndexes; i++) {
      const t = r.buf[r.pos + i];
      lenlog2[i] = t >> 4;
      idxs[i] = t & 0xF;
    }
    numLens = numIndexes;
  } else {
    const chunk = numIndexes - arrayCount;
    const r = decodeBytes(src, pos, end, numIndexes, null, 0);
    if (r.size !== numIndexes) fail('multiarray: index size mismatch');
    pos += r.used;
    idxs = r.buf.slice(r.pos, r.pos + r.size);
    const r2 = decodeBytes(src, pos, end, chunk, null, 0);
    if (r2.size !== chunk) fail('multiarray: length size mismatch');
    pos += r2.used;
    lenlog2 = r2.buf.slice(r2.pos, r2.pos + r2.size);
    for (let i = 0; i < chunk; i++) if (lenlog2[i] > 16) fail('multiarray: bad length');
  }
  const decoded = new Uint32Array(numLens);
  const varbitsComplen = Q & 0x3FFF;
  if (end - pos < varbitsComplen) fail('multiarray: truncated varbits');
  const regionStart = pos, srcEndActual = pos + varbitsComplen;
  const rd = (i) => (i >= regionStart && i < srcEndActual ? src[i] : 0);
  const be32 = (i) => ((rd(i) << 24) | (rd(i + 1) << 16) | (rd(i + 2) << 8) | rd(i + 3)) >>> 0;
  const le32 = (i) => (rd(i) | (rd(i + 1) << 8) | (rd(i + 2) << 16) | (rd(i + 3) << 24)) >>> 0;
  let f = pos, bitsF = 0, bitposF = 24;
  let b = srcEndActual, bitsB = 0, bitposB = 24;
  let i;
  for (i = 0; i + 2 <= numLens; i += 2) {
    bitsF = (bitsF | (be32(f) >>> (24 - bitposF))) >>> 0;
    f += (bitposF + 7) >> 3;
    bitsB = (bitsB | (le32(b - 4) >>> (24 - bitposB))) >>> 0;
    b -= (bitposB + 7) >> 3;
    const nf = lenlog2[i], nb = lenlog2[i + 1];
    bitsF = rotl(bitsF | 1, nf);
    bitposF += nf - 8 * ((bitposF + 7) >> 3);
    bitsB = rotl(bitsB | 1, nb);
    bitposB += nb - 8 * ((bitposB + 7) >> 3);
    decoded[i] = bitsF & BITMASKS[nf];
    bitsF = (bitsF & ~BITMASKS[nf]) >>> 0;
    decoded[i + 1] = bitsB & BITMASKS[nb];
    bitsB = (bitsB & ~BITMASKS[nb]) >>> 0;
  }
  if (i < numLens) {
    bitsF = (bitsF | (be32(f) >>> (24 - bitposF))) >>> 0;
    const nf = lenlog2[i];
    bitsF = rotl(bitsF | 1, nf);
    decoded[i] = bitsF & BITMASKS[nf];
  }
  if (idxs[numIndexes - 1]) fail('multiarray: bad index terminator');
  let indi = 0, leni = 0, source;
  const incLeni = (Q & 0x8000) ? 1 : 0;
  for (let arri = 0; arri < arrayCount; arri++) {
    if (indi >= numIndexes) fail('multiarray: index overrun');
    while ((source = idxs[indi++]) !== 0) {
      if (source > nArr) fail('multiarray: bad source');
      if (leni >= numLens) fail('multiarray: length overrun');
      const curLen = decoded[leni++];
      const e = ent[source - 1];
      if (curLen > e.size || curLen > dEnd - d) fail('multiarray: overflow');
      dst.set(e.buf.subarray(e.p, e.p + curLen), d);
      e.p += curLen; e.size -= curLen; d += curLen;
    }
    leni += incLeni;
  }
  if (indi !== numIndexes || leni !== numLens) fail('multiarray: count mismatch');
  for (const e of ent) if (e.size) fail('multiarray: leftover data');
  return { used: srcEndActual - org, size: total };
}

function decodeRecursive(src, pos, srcSize, out, o, outSize) {
  const end = pos + srcSize, oEnd = o + outSize;
  if (srcSize < 6) fail('recursive: too small');
  const n0 = src[pos] & 0x7f;
  if (n0 < 2) fail('recursive: bad count');
  if (!(src[pos] & 0x80)) {
    let p = pos + 1;
    for (let k = 0; k < n0; k++) {
      const r = decodeBytes(src, p, end, oEnd - o, out, o);
      o += r.size;
      p += r.used;
    }
    if (o !== oEnd) fail('recursive: size mismatch');
    return p - pos;
  }
  const r = decodeMultiArray(src, pos, end, out, o, oEnd, 1);
  if (o + r.size !== oEnd) fail('recursive: size mismatch');
  return r.used;
}

// ---------------------------------------------------------------------------
// DecodeBytes: decodes one entropy-coded chunk starting at src[pos] (not past |end|).
// If |dst| is given the output is written at dst[dstPos..]; otherwise a new buffer is
// allocated (or, for memcopy chunks, a view into |src| is returned).
// Returns { used: source bytes consumed, size: decoded size, buf, pos }.
function decodeBytes(src, pos, end, outCap, dst, dstPos) {
  if (end - pos < 2) fail('entropy: truncated chunk header');
  const b0 = src[pos];
  const type = (b0 >> 4) & 7;
  if (type === 0) {
    let size, p;
    if (b0 >= 0x80) {
      size = ((b0 << 8) | src[pos + 1]) & 0xFFF;
      p = pos + 2;
    } else {
      if (end - pos < 3) fail('entropy: truncated chunk header');
      size = (b0 << 16) | (src[pos + 1] << 8) | src[pos + 2];
      if (size & ~0x3ffff) fail('entropy: reserved bits set');
      p = pos + 3;
    }
    if (size > outCap || end - p < size) fail('entropy: memcopy chunk out of range');
    if (dst) {
      dst.set(src.subarray(p, p + size), dstPos);
      return { used: p + size - pos, size, buf: dst, pos: dstPos };
    }
    return { used: p + size - pos, size, buf: src, pos: p };
  }
  let srcSize, dstSize, p;
  if (b0 >= 0x80) {
    if (end - pos < 3) fail('entropy: truncated chunk header');
    const bits = (b0 << 16) | (src[pos + 1] << 8) | src[pos + 2];
    srcSize = bits & 0x3ff;
    dstSize = srcSize + ((bits >> 10) & 0x3ff) + 1;
    p = pos + 3;
  } else {
    if (end - pos < 5) fail('entropy: truncated chunk header');
    const bits = ((src[pos + 1] << 24) | (src[pos + 2] << 16) | (src[pos + 3] << 8) | src[pos + 4]) >>> 0;
    srcSize = bits & 0x3ffff;
    dstSize = (((bits >>> 18) | (b0 << 14)) & 0x3FFFF) + 1;
    if (srcSize >= dstSize) fail('entropy: bad chunk sizes');
    p = pos + 5;
  }
  if (end - p < srcSize || dstSize > outCap) fail('entropy: chunk out of range');
  let out = dst, o = dstPos;
  if (!out) { out = new Uint8Array(dstSize); o = 0; }
  let used;
  switch (type) {
    case 2: case 4: used = decodeHuff(src, p, srcSize, out, o, dstSize, type >> 1); break;
    case 5: used = decodeRecursive(src, p, srcSize, out, o, dstSize); break;
    case 3: used = decodeRle(src, p, srcSize, out, o, dstSize); break;
    case 1: used = decodeTans(src, p, srcSize, out, o, dstSize); break;
    default: fail(`entropy: unknown chunk type ${type}`);
  }
  if (used !== srcSize) fail('entropy: chunk size mismatch');
  return { used: p + srcSize - pos, size: dstSize, buf: out, pos: o };
}

module.exports = { decodeBytes, OodleError, fail, BitReader };
