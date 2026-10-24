// QR Code Generator (ISO/IEC 18004) in pure TypeScript.
// Self-contained implementation without external dependencies, supporting Byte mode,
// Reed-Solomon error correction (Level M), SVG and Canvas/PNG rendering.

// GF(256) with primitive polynomial 0x11d (x^8 + x^4 + x^3 + x^2 + 1)
const GF_EXP = new Uint8Array(512);
const GF_LOG = new Uint8Array(256);

(() => {
  let x = 1;
  for (let i = 0; i < 255; i++) {
    GF_EXP[i] = x;
    GF_EXP[i + 255] = x;
    GF_LOG[x] = i;
    x <<= 1;
    if (x & 0x100) x ^= 0x11d;
  }
})();

function gfMul(x: number, y: number): number {
  if (x === 0 || y === 0) return 0;
  return GF_EXP[GF_LOG[x] + GF_LOG[y]];
}

function rsGeneratorPoly(degree: number): Uint8Array {
  let poly = new Uint8Array([1]);
  for (let i = 0; i < degree; i++) {
    const next = new Uint8Array(poly.length + 1);
    for (let j = 0; j < poly.length; j++) {
      next[j] ^= gfMul(poly[j], GF_EXP[i]);
      next[j + 1] ^= poly[j];
    }
    poly = next;
  }
  return poly;
}

function rsComputeRemainder(data: Uint8Array, numEcBytes: number): Uint8Array {
  const gen = rsGeneratorPoly(numEcBytes);
  const remainder = new Uint8Array(numEcBytes);
  for (let i = 0; i < data.length; i++) {
    const factor = data[i] ^ remainder[0];
    remainder.copyWithin(0, 1);
    remainder[numEcBytes - 1] = 0;
    for (let j = 0; j < numEcBytes; j++) {
      remainder[j] ^= gfMul(gen[j], factor);
    }
  }
  return remainder;
}

// Table of QR versions: total data capacity and EC codewords for Level M
interface VersionInfo {
  version: number;
  totalDataBytes: number;
  ecBytesPerBlock: number;
  numBlocks: number;
  alignmentPatterns: number[];
}

const VERSION_TABLE_M: VersionInfo[] = [
  { version: 1, totalDataBytes: 16, ecBytesPerBlock: 10, numBlocks: 1, alignmentPatterns: [] },
  { version: 2, totalDataBytes: 28, ecBytesPerBlock: 16, numBlocks: 1, alignmentPatterns: [6, 18] },
  { version: 3, totalDataBytes: 44, ecBytesPerBlock: 26, numBlocks: 1, alignmentPatterns: [6, 22] },
  { version: 4, totalDataBytes: 64, ecBytesPerBlock: 18, numBlocks: 2, alignmentPatterns: [6, 26] },
  { version: 5, totalDataBytes: 86, ecBytesPerBlock: 24, numBlocks: 2, alignmentPatterns: [6, 30] },
  { version: 6, totalDataBytes: 108, ecBytesPerBlock: 16, numBlocks: 4, alignmentPatterns: [6, 34] },
  { version: 7, totalDataBytes: 124, ecBytesPerBlock: 18, numBlocks: 4, alignmentPatterns: [6, 22, 38] },
  { version: 8, totalDataBytes: 154, ecBytesPerBlock: 22, numBlocks: 4, alignmentPatterns: [6, 24, 42] },
  { version: 9, totalDataBytes: 182, ecBytesPerBlock: 22, numBlocks: 5, alignmentPatterns: [6, 26, 46] },
  { version: 10, totalDataBytes: 216, ecBytesPerBlock: 26, numBlocks: 5, alignmentPatterns: [6, 28, 50] },
  { version: 11, totalDataBytes: 254, ecBytesPerBlock: 30, numBlocks: 5, alignmentPatterns: [6, 30, 54] },
  { version: 12, totalDataBytes: 290, ecBytesPerBlock: 22, numBlocks: 8, alignmentPatterns: [6, 32, 58] },
  { version: 13, totalDataBytes: 334, ecBytesPerBlock: 22, numBlocks: 9, alignmentPatterns: [6, 34, 62] },
  { version: 14, totalDataBytes: 365, ecBytesPerBlock: 24, numBlocks: 9, alignmentPatterns: [6, 26, 46, 66] },
];

export class BitBuffer {
  private buffer: number[] = [];
  public length = 0;

  put(num: number, length: number) {
    for (let i = 0; i < length; i++) {
      this.putBit(((num >>> (length - i - 1)) & 1) === 1);
    }
  }

  putBit(bit: boolean) {
    const bufIndex = Math.floor(this.length / 8);
    if (this.buffer.length <= bufIndex) {
      this.buffer.push(0);
    }
    if (bit) {
      this.buffer[bufIndex] |= 0x80 >>> (this.length % 8);
    }
    this.length++;
  }

  getBytes(): Uint8Array {
    return new Uint8Array(this.buffer);
  }
}

export function encodeQrCode(text: string): { matrix: boolean[][]; size: number } {
  const utf8Bytes = new TextEncoder().encode(text);
  const dataLen = utf8Bytes.length;

  // Find lowest version supporting this byte length
  let selectedVersion: VersionInfo | null = null;
  for (const v of VERSION_TABLE_M) {
    // 4 bits mode + 8 bits char count + dataLen * 8 bits
    const requiredBits = 4 + 8 + dataLen * 8;
    if (Math.ceil(requiredBits / 8) <= v.totalDataBytes) {
      selectedVersion = v;
      break;
    }
  }

  if (!selectedVersion) {
    selectedVersion = VERSION_TABLE_M[VERSION_TABLE_M.length - 1];
  }

  const bb = new BitBuffer();
  // 1. Mode indicator: Byte mode (0100)
  bb.put(0x04, 4);
  // 2. Character count indicator (8 bits for versions 1-9, 16 bits for version >= 10)
  bb.put(dataLen, selectedVersion.version < 10 ? 8 : 16);
  // 3. Data bytes
  for (let i = 0; i < dataLen; i++) {
    bb.put(utf8Bytes[i], 8);
  }

  // 4. Terminator
  const maxBits = selectedVersion.totalDataBytes * 8;
  const termBits = Math.min(4, maxBits - bb.length);
  bb.put(0, termBits);

  // 5. Pad to multiple of 8
  while (bb.length % 8 !== 0) {
    bb.putBit(false);
  }

  // 6. Fill with alternate padding bytes 0xEC, 0x11
  let padByte = 0xec;
  while (bb.length < maxBits) {
    bb.put(padByte, 8);
    padByte = padByte === 0xec ? 0x11 : 0xec;
  }

  const rawData = bb.getBytes().slice(0, selectedVersion.totalDataBytes);

  // Divide into blocks and compute Reed-Solomon EC
  const { numBlocks, totalDataBytes, ecBytesPerBlock } = selectedVersion;
  const baseBlockDataLen = Math.floor(totalDataBytes / numBlocks);
  const numLargerBlocks = totalDataBytes % numBlocks;

  const dataBlocks: Uint8Array[] = [];
  const ecBlocks: Uint8Array[] = [];
  let offset = 0;

  for (let b = 0; b < numBlocks; b++) {
    const blockLen = b >= numBlocks - numLargerBlocks ? baseBlockDataLen + 1 : baseBlockDataLen;
    const blockData = rawData.slice(offset, offset + blockLen);
    offset += blockLen;
    dataBlocks.push(blockData);
    ecBlocks.push(rsComputeRemainder(blockData, ecBytesPerBlock));
  }

  // Interleave data codewords
  const interleaved: number[] = [];
  const maxDataBlockLen = baseBlockDataLen + (numLargerBlocks > 0 ? 1 : 0);
  for (let i = 0; i < maxDataBlockLen; i++) {
    for (let b = 0; b < numBlocks; b++) {
      if (i < dataBlocks[b].length) {
        interleaved.push(dataBlocks[b][i]);
      }
    }
  }

  // Interleave EC codewords
  for (let i = 0; i < ecBytesPerBlock; i++) {
    for (let b = 0; b < numBlocks; b++) {
      interleaved.push(ecBlocks[b][i]);
    }
  }

  // Build 2D matrix
  const version = selectedVersion.version;
  const matrixSize = version * 4 + 17;
  const matrix: (boolean | null)[][] = Array.from({ length: matrixSize }, () =>
    Array(matrixSize).fill(null),
  );
  const isFunction: boolean[][] = Array.from({ length: matrixSize }, () =>
    Array(matrixSize).fill(false),
  );

  function setModule(r: number, c: number, val: boolean, fn = true) {
    matrix[r][c] = val;
    if (fn) isFunction[r][c] = true;
  }

  // Finder pattern helper (7x7)
  function placeFinder(r: number, c: number) {
    for (let dr = -1; dr <= 7; dr++) {
      for (let dc = -1; dc <= 7; dc++) {
        const nr = r + dr;
        const nc = c + dc;
        if (nr >= 0 && nr < matrixSize && nc >= 0 && nc < matrixSize) {
          const isBlack =
            (dr >= 0 && dr <= 6 && (dc === 0 || dc === 6)) ||
            (dc >= 0 && dc <= 6 && (dr === 0 || dr === 6)) ||
            (dr >= 2 && dr <= 4 && dc >= 2 && dc <= 4);
          setModule(nr, nc, isBlack);
        }
      }
    }
  }

  placeFinder(0, 0);
  placeFinder(0, matrixSize - 7);
  placeFinder(matrixSize - 7, 0);

  // Timing patterns
  for (let i = 8; i < matrixSize - 8; i++) {
    setModule(6, i, i % 2 === 0);
    setModule(i, 6, i % 2 === 0);
  }

  // Alignment patterns
  const alignCoords = selectedVersion.alignmentPatterns;
  for (let rIdx = 0; rIdx < alignCoords.length; rIdx++) {
    for (let cIdx = 0; cIdx < alignCoords.length; cIdx++) {
      const ar = alignCoords[rIdx];
      const ac = alignCoords[cIdx];
      // Skip finders
      if (
        (ar === 6 && ac === 6) ||
        (ar === 6 && ac === matrixSize - 7) ||
        (ar === matrixSize - 7 && ac === 6)
      ) {
        continue;
      }
      for (let dr = -2; dr <= 2; dr++) {
        for (let dc = -2; dc <= 2; dc++) {
          const isBlack =
            Math.abs(dr) === 2 || Math.abs(dc) === 2 || (dr === 0 && dc === 0);
          setModule(ar + dr, ac + dc, isBlack);
        }
      }
    }
  }

  // Dark module
  setModule(matrixSize - 8, 8, true);

  // Reserve format bits
  for (let i = 0; i < 9; i++) {
    if (i !== 6) {
      setModule(8, i, false);
      setModule(i, 8, false);
    }
  }
  for (let i = 0; i < 8; i++) {
    setModule(8, matrixSize - 1 - i, false);
    setModule(matrixSize - 1 - i, 8, false);
  }

  // Fill data with Mask 0 ((r + c) % 2 == 0)
  let bitIndex = 0;
  const interleavedBits: boolean[] = [];
  for (const b of interleaved) {
    for (let s = 7; s >= 0; s--) {
      interleavedBits.push(((b >>> s) & 1) === 1);
    }
  }

  let upward = true;
  for (let right = matrixSize - 1; right > 0; right -= 2) {
    if (right === 6) right--; // Skip vertical timing pattern
    const rows = upward
      ? Array.from({ length: matrixSize }, (_, i) => matrixSize - 1 - i)
      : Array.from({ length: matrixSize }, (_, i) => i);

    for (const r of rows) {
      for (const colOffset of [0, 1]) {
        const c = right - colOffset;
        if (!isFunction[r][c]) {
          const bit = bitIndex < interleavedBits.length ? interleavedBits[bitIndex++] : false;
          // Apply mask 0: flip if (r + c) % 2 == 0
          const mask = (r + c) % 2 === 0;
          matrix[r][c] = bit !== mask;
        }
      }
    }
    upward = !upward;
  }

  // Level M, Mask 0 format string BCH(15, 5) XOR 0x5412: 101010000010010
  const formatBits = [
    true, false, true, false, true, false, false, false, false, false, true, false, false, true, false,
  ];

  // Write format info around top-left finder and split across top-right/bottom-left
  const formatPairs1 = [
    [8, 0], [8, 1], [8, 2], [8, 3], [8, 4], [8, 5], [8, 7], [8, 8],
    [7, 8], [5, 8], [4, 8], [3, 8], [2, 8], [1, 8], [0, 8],
  ];
  for (let i = 0; i < 15; i++) {
    const [r, c] = formatPairs1[i];
    matrix[r][c] = formatBits[i];
  }

  const formatPairs2 = [
    [matrixSize - 1, 8], [matrixSize - 2, 8], [matrixSize - 3, 8], [matrixSize - 4, 8],
    [matrixSize - 5, 8], [matrixSize - 6, 8], [matrixSize - 7, 8],
    [8, matrixSize - 8], [8, matrixSize - 7], [8, matrixSize - 6], [8, matrixSize - 5],
    [8, matrixSize - 4], [8, matrixSize - 3], [8, matrixSize - 2], [8, matrixSize - 1],
  ];
  for (let i = 0; i < 15; i++) {
    const [r, c] = formatPairs2[i];
    matrix[r][c] = formatBits[i];
  }

  const finalMatrix = matrix.map((row) => row.map((cell) => cell ?? false));
  return { matrix: finalMatrix, size: matrixSize };
}

/** Generates clean SVG markup representing the QR code. */
export function generateQrSvg(text: string, pixelSize = 240, margin = 4): string {
  const { matrix, size } = encodeQrCode(text);
  const totalDim = size + margin * 2;

  let rects = "";
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (matrix[r][c]) {
        rects += `<rect x="${c + margin}" y="${r + margin}" width="1" height="1" fill="#000000"/>`;
      }
    }
  }

  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${totalDim} ${totalDim}" width="${pixelSize}" height="${pixelSize}" shape-rendering="crispEdges">
    <rect width="${totalDim}" height="${totalDim}" fill="#ffffff"/>
    ${rects}
  </svg>`;
}

/** Exports the given QR code text as an SVG file download in the browser. */
export function downloadQrSvg(text: string, filename = "attestation-qr.svg"): void {
  const svg = generateQrSvg(text, 360, 4);
  const blob = new Blob([svg], { type: "image/svg+xml;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

/** Exports the given QR code text as a PNG image download using an offscreen canvas. */
export function downloadQrPng(text: string, filename = "attestation-qr.png", pixelSize = 512): void {
  const { matrix, size } = encodeQrCode(text);
  const margin = 4;
  const totalDim = size + margin * 2;
  const scale = Math.floor(pixelSize / totalDim) || 8;
  const realDim = totalDim * scale;

  const canvas = document.createElement("canvas");
  canvas.width = realDim;
  canvas.height = realDim;
  const ctx = canvas.getContext("2d");
  if (!ctx) return;

  // Background
  ctx.fillStyle = "#ffffff";
  ctx.fillRect(0, 0, realDim, realDim);

  // Black modules
  ctx.fillStyle = "#000000";
  for (let r = 0; r < size; r++) {
    for (let c = 0; c < size; c++) {
      if (matrix[r][c]) {
        ctx.fillRect((c + margin) * scale, (r + margin) * scale, scale, scale);
      }
    }
  }

  canvas.toBlob((blob) => {
    if (!blob) return;
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  }, "image/png");
}
