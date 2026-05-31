// RIPEMD-160 — compact, dependency-free implementation.
// Exposes window.ripemd160(Uint8Array) -> Uint8Array(20).
(function (global) {
  'use strict';

  function rotl(x, n) { return (x << n) | (x >>> (32 - n)); }

  // Message word selection
  var zl = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13
  ];
  var zr = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11
  ];
  // Rotate amounts
  var sl = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6
  ];
  var sr = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11
  ];
  // Constants per round (left and right lines)
  var hl = [0x00000000, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e];
  var hr = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0x00000000];

  function f(j, x, y, z) {
    if (j < 16) return x ^ y ^ z;
    if (j < 32) return (x & y) | (~x & z);
    if (j < 48) return (x | ~y) ^ z;
    if (j < 64) return (x & z) | (y & ~z);
    return x ^ (y | ~z);
  }

  function ripemd160(input) {
    // Pad
    var len = input.length;
    var blocks = (((len + 8) >> 6) + 1);
    var total = blocks * 64;
    var m = new Uint8Array(total);
    m.set(input);
    m[len] = 0x80;
    // length in bits, little-endian, 64-bit (we only fill low 53 bits safely)
    var bitLenLo = (len << 3) >>> 0;
    var bitLenHi = Math.floor(len / 0x20000000) >>> 0;
    var lenOff = total - 8;
    m[lenOff] = bitLenLo & 0xff;
    m[lenOff + 1] = (bitLenLo >>> 8) & 0xff;
    m[lenOff + 2] = (bitLenLo >>> 16) & 0xff;
    m[lenOff + 3] = (bitLenLo >>> 24) & 0xff;
    m[lenOff + 4] = bitLenHi & 0xff;
    m[lenOff + 5] = (bitLenHi >>> 8) & 0xff;
    m[lenOff + 6] = (bitLenHi >>> 16) & 0xff;
    m[lenOff + 7] = (bitLenHi >>> 24) & 0xff;

    var h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
    var X = new Int32Array(16);

    for (var b = 0; b < blocks; b++) {
      var base = b * 64;
      for (var i = 0; i < 16; i++) {
        var o = base + i * 4;
        X[i] = (m[o]) | (m[o + 1] << 8) | (m[o + 2] << 16) | (m[o + 3] << 24);
      }

      var al = h0, bl = h1, cl = h2, dl = h3, el = h4;
      var ar = h0, br = h1, cr = h2, dr = h3, er = h4;

      for (var j = 0; j < 80; j++) {
        var round = j >> 4;
        var t;
        t = (al + f(j, bl, cl, dl) + X[zl[j]] + hl[round]) | 0;
        t = (rotl(t, sl[j]) + el) | 0;
        al = el; el = dl; dl = rotl(cl, 10); cl = bl; bl = t;

        var roundR = (79 - j) >> 4;
        t = (ar + f(79 - j, br, cr, dr) + X[zr[j]] + hr[round]) | 0;
        t = (rotl(t, sr[j]) + er) | 0;
        ar = er; er = dr; dr = rotl(cr, 10); cr = br; br = t;
      }

      var tmp = (h1 + cl + dr) | 0;
      h1 = (h2 + dl + er) | 0;
      h2 = (h3 + el + ar) | 0;
      h3 = (h4 + al + br) | 0;
      h4 = (h0 + bl + cr) | 0;
      h0 = tmp;
    }

    var out = new Uint8Array(20);
    var hs = [h0, h1, h2, h3, h4];
    for (var k = 0; k < 5; k++) {
      out[k * 4] = hs[k] & 0xff;
      out[k * 4 + 1] = (hs[k] >>> 8) & 0xff;
      out[k * 4 + 2] = (hs[k] >>> 16) & 0xff;
      out[k * 4 + 3] = (hs[k] >>> 24) & 0xff;
    }
    return out;
  }

  global.ripemd160 = ripemd160;
})(window);
