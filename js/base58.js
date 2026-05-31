// Base58 / Base58Check encode + decode. Exposes window.base58.
(function (global) {
  'use strict';
  var ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  var MAP = {};
  for (var i = 0; i < ALPHABET.length; i++) MAP[ALPHABET[i]] = i;

  function encode(bytes) {
    // count leading zeros
    var zeros = 0;
    while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
    var digits = [0];
    for (var i = zeros; i < bytes.length; i++) {
      var carry = bytes[i];
      for (var j = 0; j < digits.length; j++) {
        carry += digits[j] << 8;
        digits[j] = carry % 58;
        carry = (carry / 58) | 0;
      }
      while (carry > 0) {
        digits.push(carry % 58);
        carry = (carry / 58) | 0;
      }
    }
    var out = '';
    for (var z = 0; z < zeros; z++) out += '1';
    for (var k = digits.length - 1; k >= 0; k--) out += ALPHABET[digits[k]];
    return out;
  }

  function decode(str) {
    if (str.length === 0) return new Uint8Array(0);
    var bytes = [0];
    for (var i = 0; i < str.length; i++) {
      var val = MAP[str[i]];
      if (val === undefined) return null; // invalid char
      var carry = val;
      for (var j = 0; j < bytes.length; j++) {
        carry += bytes[j] * 58;
        bytes[j] = carry & 0xff;
        carry >>= 8;
      }
      while (carry > 0) { bytes.push(carry & 0xff); carry >>= 8; }
    }
    var zeros = 0;
    while (zeros < str.length && str[zeros] === '1') zeros++;
    var out = new Uint8Array(zeros + bytes.length);
    for (var k = 0; k < bytes.length; k++) out[zeros + k] = bytes[bytes.length - 1 - k];
    return out;
  }

  // version: int (0x00 mainnet P2PKH, 0x05 P2SH). payload: Uint8Array(20).
  // Requires async sha256 (Web Crypto). Returns a Promise<string>.
  async function encodeCheck(version, payload) {
    var data = new Uint8Array(1 + payload.length);
    data[0] = version;
    data.set(payload, 1);
    var checksum = await sha256d(data);
    var full = new Uint8Array(data.length + 4);
    full.set(data);
    full.set(checksum.subarray(0, 4), data.length);
    return encode(full);
  }

  async function sha256(bytes) {
    var buf = await crypto.subtle.digest('SHA-256', bytes);
    return new Uint8Array(buf);
  }
  async function sha256d(bytes) {
    return sha256(await sha256(bytes));
  }

  global.base58 = { encode: encode, decode: decode, encodeCheck: encodeCheck, sha256: sha256, sha256d: sha256d };
})(window);
