# Twotbit

A native macOS SPV Bitcoin wallet in SwiftUI: BIP84 keys, a fully
validated block header chain, BIP157/158 compact block filters and a small
pool of P2P peers, reached directly or over Tor and I2P.

Twotbit is a rebuild of [bitfyn](https://github.com/pin2t/bitfyn), the Go
and Fyne wallet, as a Mac app. The wallet engine is a Swift port of
bitfyn's, checked value for value against it, and the interface follows
its window section by section.

## Features

- **HD wallet**: a 12-word BIP39 recovery phrase and BIP84 native segwit
  (P2WPKH, bech32) receive and change addresses. A fresh address is shown
  once the current one is paid.
- **SPV header sync**: the header chain is downloaded and validated as
  Bitcoin Core validates headers — proof of work, the network's work limit,
  median time past, the future time limit and the exact difficulty of every
  header, testnet's 20-minute rule and testnet4's BIP94 included.
- **BIP157/158 compact filters**: filters are downloaded from up to three
  peers and cross-checked block by block; a disagreement is settled against
  the full block and the lying peer is dropped. The first filter header of
  the wallet's range is proven by a majority of up to ten peers. Matching
  blocks are downloaded and verified (merkle root, witness commitment);
  filters are pruned after matching.
- **Mempool**: unconfirmed payments arrive through BIP37 bloom filters on
  peers that serve them, or by checking every relayed transaction from one
  peer otherwise.
- **Send**: coin selection or hand-picked coins, change, dust and fee
  handling, BIP69 ordering, RBF, RFC 6979 signatures with libsecp256k1, and
  rebroadcast until confirmed.
- **Peers**: a pool of three compact filter peers from DNS seeds and gossip,
  per-peer statistics, failover, and an optional pinned peer that headers
  and filters are always synced from.
- **Tor and I2P**: with either on, only onion or I2P peers are used, through
  a local Tor client's SOCKS5 proxy (a fresh circuit per peer) or an I2P
  router's SAM bridge.
- **Rates**: BTC/USD history since 2010 ships with the app; fresh rates come
  from Coinbase, Kraken and Bitstamp.
- **Window**: Home (QR code, address, balance in BTC and USD, statistics),
  Coins (sortable table, multi-selection that Send starts from),
  Transactions (inputs → outputs, the wallet's own addresses in bold) and
  Settings, in light and dark mode.

## Build and run

Requires macOS 15 or later and Xcode 16 or later (developed with Xcode 27).

Open `Twotbit.xcodeproj` and run the Twotbit scheme, or:

```sh
make app      # release build in build/DerivedData/Build/Products/Release
make run      # build and open it; pass options as ARGS="-net signet"
make test     # the wallet engine's tests
```

Options, also settable with `defaults write com.pin2t.twotbit <key> <value>`:

| option      | default                                  | meaning |
|-------------|------------------------------------------|---------|
| `-net`      | `mainnet`                                | `mainnet`, `testnet`, `testnet4`, `signet`, `regtest` or `simnet`; also chosen in Settings |
| `-datadir`  | `~/Library/Application Support/Twotbit`  | where the wallet databases and `twotbit.log` live |
| `-peer`     |                                          | a `host:port` peer to pin the sync to, winning over the one saved in Settings |
| `-torproxy` | `127.0.0.1:9050`, then `127.0.0.1:9150`  | the Tor client's SOCKS5 proxy (the tor daemon, Tor Browser) |
| `-i2psam`   | `127.0.0.1:7656`                         | the I2P router's SAM bridge (i2pd, Java I2P) |

For example `open Twotbit.app --args -net signet`.

### The recovery phrase and the Keychain

The recovery phrase is kept in the login Keychain; the database holds only
public data. Settings shows the phrase after Touch ID or your password, and
if the Keychain ever loses it, the app asks for the 12 words to restore it.
The local test networks, regtest and simnet, keep their phrase in the
database instead.

macOS ties Keychain access to the app's code signature. Builds signed to
run locally get a new signature with every build, so after a rebuild macOS
asks once whether Twotbit may read its Keychain item. Choosing your team
under Signing & Capabilities keeps the signature stable and avoids that.

### Moving a bitfyn wallet over

Twotbit uses bitfyn's database schema. To continue with an unencrypted
bitfyn wallet, quit both apps and copy the database across, such as
`~/.bitfyn/bitfyn.db` to `~/Library/Application Support/Twotbit/twotbit.db`
(`bitfyn-signet.db` to `twotbit-signet.db`, and so on). On first open the
phrase moves from the database into the Keychain; the synced headers,
filters and transactions carry over.

## How it differs from bitfyn

- The window is a native Mac app: a sidebar for bitfyn's tabs, a sortable
  table for coins, sheets for Receive and Send, the connection status in the
  toolbar, and menu commands with shortcuts.
- The recovery phrase lives in the Keychain rather than in the database; a
  SQLCipher passphrase (`-dbpass`) is no longer needed. Settings adds the
  network switch, the account public key (zpub/vpub), the data folder and
  the recovery phrase.
- Tor goes through a local Tor client's SOCKS5 proxy instead of a Tor client
  compiled into the app, with stream isolation per peer.
- Header validation is stricter, matching Bitcoin Core: every header must
  carry exactly the required difficulty and stay within the network's work
  limit, and a reorganisation is taken only for a branch with more proof of
  work.
- Fixed while porting: after a peer dropped during the filter sync, bitfyn
  checked the remaining peers' filters against the wrong peer's filter
  hashes.
- QR codes are drawn dark on light with a quiet zone in both appearances,
  so every scanner reads them.
- Not ported: the `-check` smoke mode and the developer tools (`gentx`,
  `btcnodes`, `hdwalk`).

## Layout

```
App/                   the SwiftUI app: AppModel (the GUI logic), the views, assets
Core/                  Swift package TwotbitCore
  Sources/CSecp256k1   libsecp256k1 v0.6.0, vendored unchanged
  Sources/TwotbitKit   the wallet engine
    Crypto             hashes, RIPEMD-160, SHA3, SipHash, Murmur3, secp256k1
    Encoding           Base58Check, Bech32/Bech32m, Base32
    Bitcoin            networks, headers, transactions, blocks, scripts, addresses
    Wallet             BIP39, BIP32, the BIP84 wallet, coin selection and signing
    SPV                the validated header chain, GCS and bloom filters
    P2P                wire messages, TCP, peers, Tor (SOCKS5) and I2P (SAM)
    Sync               the peer pool, header, filter and wallet sync, rescans
    Storage            SQLite store, Keychain, wallet loading
    Rates, Format      BTC/USD rates; amounts, times, statistics, QR codes
  Tests/TwotbitKitTests
Scripts/make-icon.swift  draws the app icon
```

## Tests

`make test` runs 80-odd tests in a few seconds:

- crypto, encoding, BIP39/BIP32/BIP84, coin selection and signing against
  vectors generated from bitfyn and btcd — signed transactions match bitfyn
  byte for byte;
- network parameters, difficulty and retargets, the first 4100 mainnet
  headers, GCS filters of real blocks, bloom filters, block verification
  and every wire message btcd writes;
- the database, wallet loading and the Keychain migration of bitfyn
  databases;
- end-to-end syncs against in-process mock Bitcoin nodes over local TCP:
  payments and spends, a lying peer outvoted by the full block, relayed and
  broadcast transactions, reorganisations, the filter anchor majority,
  rescans, pinned peers, and Tor and I2P through mock proxies.

Opt-in tests, set by environment variables:

```sh
# validate whole stored chains, read-only, such as bitfyn's
TWOTBIT_CHAIN_DB="mainnet=$HOME/.bitfyn/bitfyn.db" swift test --package-path Core -c release --filter realChains
# sync a fresh wallet from the real network
TWOTBIT_LIVE=signet swift test --package-path Core -c release --filter LiveTests
# build a demo regtest wallet to open with -net regtest -datadir <dir>
TWOTBIT_DEMO_DIR=/tmp/demo swift test --package-path Core --filter DemoWallet
```

`TWOTBIT_LOG_STDERR=1` echoes the wallet's log while they run. Debug
builds of the app also take `-snapshot <dir>`, which saves every section
and sheet as PNG images, light and dark, and quits.

## License

MIT, see [LICENSE](../LICENSE). libsecp256k1 is MIT licensed too, see
`Core/Sources/CSecp256k1/COPYING`.
