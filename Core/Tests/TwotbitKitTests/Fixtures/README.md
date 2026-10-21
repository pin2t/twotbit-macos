# Test fixtures

Generated from the Go implementation this wallet was ported from and the
btcd libraries it builds on, so the Swift code is checked against
them value for value:

- `wallet.json` — BIP39 mnemonics and seeds, BIP84 addresses and account
  xpubs on every network, address decoding, size and dust estimates, and
  planned and signed spends (`internal/wallet`).
- `spv.json` — network parameters, compact difficulty bits, retargets, GCS
  filters built with btcd's builder, BIP158 filters of real mainnet blocks
  with their filter headers, and blocks with and without valid witness
  commitments (`internal/spv`, btcd `blockchain`, `btcutil/gcs`).
- `sync.json` — addresses read from input and output scripts, wallet
  histories and balances, bloom filters, MurmurHash3, SipHash and filter
  anchor majorities (`internal/sync`, btcd `btcutil/bloom`).
- `p2p.json` — wire messages as btcd writes them, onion and I2P names and
  the built-in onion and I2P seeds (`internal/p2p`, btcd `wire`).
- `mainnet-headers-0-4099.bin` — the first 4100 mainnet block headers, 80
  bytes each, from btcd's `blockchain/testdata/blk_0_to_14131.dat`.

All values come from public test data or seeded pseudo-random inputs.
