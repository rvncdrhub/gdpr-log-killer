# wallet.dat Address Explorer

A single-page tool that reads a Bitcoin Core `wallet.dat`, extracts the **public
addresses** it contains, and shows which ones currently hold a balance — with a
link to a block explorer for each.

## 🔒 Safety / privacy model (read this)

A `wallet.dat` file contains **private keys**. This tool is built so those keys
never matter and never move:

- **The file is parsed entirely in your browser.** It is read with the local
  `FileReader` API and processed in JavaScript on your machine. It is **never
  uploaded** to any server — there is no backend.
- **Only public addresses leave your machine.** To look up balances, the tool
  sends the derived *addresses* (which are public by design) to a public block
  explorer API (mempool.space or blockstream.info). Private keys are never read
  into the output, displayed, transmitted, or stored.
- **Verify it yourself:** load the page, turn off your network, drop the file
  (addresses appear), then reconnect only to fetch balances. The whole thing is
  plain static HTML/JS with no build step — read the source.

> ⚠️ Never upload a `wallet.dat` to a website that asks you to. Any site that
> receives your `wallet.dat` on a server can drain your funds. This tool
> deliberately avoids that by running client-side only.

## How it works

1. **Pubkey scan** — Berkeley-DB wallet records store public keys
   length-prefixed (`0x21` + 33-byte compressed, or `0x41` + 65-byte
   uncompressed). The parser finds these and derives, for each key:
   - P2PKH (`1…`)
   - P2WPKH / native segwit (`bc1…`, compressed keys only)
   - P2SH-P2WPKH / wrapped segwit (`3…`, compressed keys only)
2. **Address-book scan** — already-formatted addresses stored in label/`name`
   records are matched and checksum-validated.
3. **Balance lookup** — each unique address is queried against the selected
   explorer; results are filtered (default: only addresses with a balance) and
   sorted by balance.

All address derivation (RIPEMD-160, Base58Check, Bech32) is implemented locally
and verified against the BIP test vectors.

## Usage

It's static — no install, no server.

```bash
# just open it
xdg-open index.html       # Linux
open index.html           # macOS

# or serve it statically if your browser blocks file:// fetches
python3 -m http.server 8000
# then visit http://localhost:8000
```

Drop your `wallet.dat` onto the page.

## Limitations

- **Encrypted wallets:** if the wallet is encrypted, public keys are usually
  still readable, but some may not be. To be thorough, unlock/decrypt the wallet
  in Bitcoin Core first if results look incomplete.
- **HD wallets:** this reads keys/addresses already present in the file. It does
  not derive an unbounded HD address gap beyond what the wallet has generated.
- **Heuristic scanning** can occasionally surface candidate addresses that were
  never actually used; these are filtered out automatically because they have no
  on-chain balance or transaction history.
- Bitcoin mainnet only.

## Files

```
index.html        UI
styles.css        styling
js/ripemd160.js   RIPEMD-160 (for hash160)
js/base58.js      Base58 / Base58Check + SHA-256 (Web Crypto)
js/bech32.js      Bech32 segwit encoder
js/parser.js      wallet.dat byte scanner + address derivation
js/app.js         file handling, balance lookups, rendering
```
