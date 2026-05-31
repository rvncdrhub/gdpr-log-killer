// Bech32 (BIP173) encoder for native segwit v0 (P2WPKH) addresses.
// Exposes window.bech32.encodeSegwit(hrp, witnessVersion, programBytes).
(function (global) {
  'use strict';
  var CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';
  var GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];

  function polymod(values) {
    var chk = 1;
    for (var p = 0; p < values.length; p++) {
      var top = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ values[p];
      for (var i = 0; i < 5; i++) {
        if ((top >> i) & 1) chk ^= GEN[i];
      }
    }
    return chk;
  }

  function hrpExpand(hrp) {
    var ret = [];
    for (var i = 0; i < hrp.length; i++) ret.push(hrp.charCodeAt(i) >> 5);
    ret.push(0);
    for (var j = 0; j < hrp.length; j++) ret.push(hrp.charCodeAt(j) & 31);
    return ret;
  }

  function createChecksum(hrp, data) {
    var values = hrpExpand(hrp).concat(data).concat([0, 0, 0, 0, 0, 0]);
    var mod = polymod(values) ^ 1;
    var ret = [];
    for (var p = 0; p < 6; p++) ret.push((mod >> (5 * (5 - p))) & 31);
    return ret;
  }

  function encode(hrp, data) {
    var combined = data.concat(createChecksum(hrp, data));
    var ret = hrp + '1';
    for (var i = 0; i < combined.length; i++) ret += CHARSET.charAt(combined[i]);
    return ret;
  }

  // Convert 8-bit bytes to 5-bit groups (for witness program).
  function convertBits(data, fromBits, toBits, pad) {
    var acc = 0, bits = 0, ret = [];
    var maxv = (1 << toBits) - 1;
    for (var i = 0; i < data.length; i++) {
      var value = data[i];
      if (value < 0 || value >> fromBits !== 0) return null;
      acc = (acc << fromBits) | value;
      bits += fromBits;
      while (bits >= toBits) { bits -= toBits; ret.push((acc >> bits) & maxv); }
    }
    if (pad) { if (bits > 0) ret.push((acc << (toBits - bits)) & maxv); }
    else if (bits >= fromBits || ((acc << (toBits - bits)) & maxv)) return null;
    return ret;
  }

  // hrp: 'bc' mainnet. witnessVersion: 0. program: Uint8Array(20) for P2WPKH.
  function encodeSegwit(hrp, witnessVersion, program) {
    var conv = convertBits(Array.from(program), 8, 5, true);
    if (conv === null) return null;
    return encode(hrp, [witnessVersion].concat(conv));
  }

  global.bech32 = { encodeSegwit: encodeSegwit };
})(window);
