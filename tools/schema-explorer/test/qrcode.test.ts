import { describe, expect, it } from "vitest";
import { encodeQrCode, generateQrSvg } from "../src/qrcode.js";

describe("QR Code Generator (#485)", () => {
  it("generates a valid QR code matrix for attestation deep links", () => {
    const url = "https://sas.stellar.org/verify?verify=1&uid=3b08e2a1490226cfa877c8e9bda53243f721d092d6e4a2bc1d8c199209581f5c";
    const { matrix, size } = encodeQrCode(url);

    expect(size).toBeGreaterThanOrEqual(21);
    expect(matrix.length).toBe(size);
    expect(matrix[0].length).toBe(size);

    // Verify top-left finder pattern is present (7x7)
    expect(matrix[0][0]).toBe(true);
    expect(matrix[0][6]).toBe(true);
    expect(matrix[6][0]).toBe(true);
    expect(matrix[6][6]).toBe(true);
    // Center of finder is black
    expect(matrix[3][3]).toBe(true);
  });

  it("produces valid, scalable SVG markup", () => {
    const url = "https://sas.stellar.org/verify?verify=1&uid=abcd";
    const svg = generateQrSvg(url, 300, 4);

    expect(svg).toContain("<svg");
    expect(svg).toContain('xmlns="http://www.w3.org/2000/svg"');
    expect(svg).toContain('width="300"');
    expect(svg).toContain('height="300"');
    expect(svg).toContain("<rect");
    expect(svg).toContain("</svg>");
  });
});
