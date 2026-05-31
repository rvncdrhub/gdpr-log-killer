// Extracts public Bitcoin addresses from a raw wallet.dat byte buffer.
//
// Strategy (all local, no network):
//  1. Scan for length-prefixed public keys the way Berkeley-DB wallet records
//     store them: 0x21 + (0x02|0x03) + 32 bytes (compressed), or
//     0x41 + 0x04 + 64 bytes (uncompressed). Derive P2PKH / P2WPKH / P2SH-P2WPKH.
//  2. Scan the bytes (as latin1 text) for already-formatted address strings
//     stored in address-book / "name" records, validating their checksums.
//
// Returns a Promise<Array<{address, type, source}>> with duplicates removed.
(function (global) {
  'use strict';

  async function hash160(bytes) {
    var sha = await base58.sha256(bytes);
    return ripemd160(sha);
  }

  function looksLikePubkey(buf, i) {
    var lp = buf[i];
    if (lp === 0x21 && (buf[i + 1] === 0x02 || buf[i + 1] === 0x03)) return 33;
    if (lp === 0x41 && buf[i + 1] === 0x04) return 65;
    return 0;
  }

  async function deriveFromPubkey(pubkey, compressed, out, seen) {
    var pkh = await hash160(pubkey);

    // P2PKH (version 0x00)
    var p2pkh = await base58.encodeCheck(0x00, pkh);
    add(out, seen, p2pkh, compressed ? 'P2PKH (compressed)' : 'P2PKH (uncompressed)', 'pubkey');

    if (compressed) {
      // P2WPKH native segwit (bech32) — only valid for compressed keys
      var p2wpkh = bech32.encodeSegwit('bc', 0, pkh);
      if (p2wpkh) add(out, seen, p2wpkh, 'P2WPKH (segwit)', 'pubkey');

      // P2SH-P2WPKH (wrapped segwit): hash160 of redeemScript 0x0014<pkh>
      var redeem = new Uint8Array(22);
      redeem[0] = 0x00; redeem[1] = 0x14; redeem.set(pkh, 2);
      var rh = await hash160(redeem);
      var p2sh = await base58.encodeCheck(0x05, rh);
      add(out, seen, p2sh, 'P2SH-P2WPKH', 'pubkey');
    }
  }

  function add(out, seen, address, type, source) {
    if (seen.has(address)) return;
    seen.add(address);
    out.push({ address: address, type: type, source: source });
  }

  // Validate an embedded base58check string and classify it.
  async function classifyBase58(str) {
    var raw = base58.decode(str);
    if (!raw || raw.length !== 25) return null; // 1 version + 20 payload + 4 checksum
    var body = raw.subarray(0, 21);
    var checksum = raw.subarray(21);
    var calc = await base58.sha256d(body);
    for (var i = 0; i < 4; i++) if (calc[i] !== checksum[i]) return null;
    if (raw[0] === 0x00) return 'P2PKH';
    if (raw[0] === 0x05) return 'P2SH';
    return null;
  }

  async function scanEmbeddedStrings(buf, out, seen) {
    // Decode as latin1 so every byte maps to one char; addresses are ASCII.
    var text = '';
    var CHUNK = 0x10000;
    for (var off = 0; off < buf.length; off += CHUNK) {
      text += String.fromCharCode.apply(null, buf.subarray(off, Math.min(off + CHUNK, buf.length)));
    }

    var b58re = /[13][a-km-zA-HJ-NP-Z1-9]{25,34}/g;
    var m;
    while ((m = b58re.exec(text)) !== null) {
      var type = await classifyBase58(m[0]);
      if (type) add(out, seen, m[0], type + ' (address-book)', 'embedded');
    }

    // Native segwit strings (basic shape check; balance lookup will confirm)
    var bechre = /bc1[ac-hj-np-z02-9]{11,71}/g;
    while ((m = bechre.exec(text)) !== null) {
      add(out, seen, m[0], 'bech32 (address-book)', 'embedded');
    }
  }

  async function extractAddresses(arrayBuffer) {
    var buf = new Uint8Array(arrayBuffer);
    var out = [];
    var seen = new Set();

    // 1. Length-prefixed pubkeys
    var n = buf.length;
    for (var i = 0; i + 2 < n; i++) {
      var klen = looksLikePubkey(buf, i);
      if (!klen) continue;
      if (i + 1 + klen > n) continue;
      var pubkey = buf.subarray(i + 1, i + 1 + klen);
      await deriveFromPubkey(pubkey, klen === 33, out, seen);
      i += klen; // skip past this key
    }

    // 2. Embedded address strings
    await scanEmbeddedStrings(buf, out, seen);

    return out;
  }

  global.walletParser = { extractAddresses: extractAddresses };
})(window);
