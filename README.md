## Blockchain Wallet CLIs (Rust and Go)

Two standalone CLI wallets are included:

- `rust-wallet`: Mnemonic, keypair derivation, Ethereum-style address, sign, verify
- `go-wallet`: Same features using Go

### Prerequisites

- Windows PowerShell
- Rust (via rustup)
- Go 1.20+

### Build

Rust:

```powershell
cd "C:\Users\User\Desktop\RUST PROJECT\rust-wallet"
cargo build
```

Go:

```powershell
cd "C:\Users\User\Desktop\RUST PROJECT\go-wallet"
go build
```

### Usage (Examples)

Rust wallet:

```powershell
# Generate 12-word mnemonic
cargo run -- mnemonic --words 12

# Derive keypair
cargo run -- keypair --mnemonic "<mnemonic>" --path "m/44'/60'/0'/0/0"

# Address
cargo run -- address --mnemonic "<mnemonic>" --path "m/44'/60'/0'/0/0"

# Sign hex message
cargo run -- sign --mnemonic "<mnemonic>" --path "m/44'/60'/0'/0/0" --message 0x68656c6c6f

# Verify (compressed SEC1 pubkey, DER sig)
cargo run -- verify --pubkey 0x<compressed_pub> --message 0x68656c6c6f --signature 0x<der_sig>
```

Go wallet:

```powershell
./go-wallet.exe mnemonic --words 12
./go-wallet.exe keypair --mnemonic "<mnemonic>" --path "m/44'/60'/0'/0/0"
./go-wallet.exe address --mnemonic "<mnemonic>" --path "m/44'/60'/0'/0/0"
./go-wallet.exe sign --mnemonic "<mnemonic>" --path "m/44'/60'/0'/0/0" --message 0x68656c6c6f
./go-wallet.exe verify --pubkey 0x04<uncompressed_pub> --message 0x68656c6c6f --signature 0x<sig65>
```

Notes:

- Rust uses DER signatures and compressed pubkeys for verification; Go uses 65-byte Ethereum-style signatures (R||S||V) and uncompressed pubkeys.
- Addresses are Ethereum-style: Keccak-256 of the uncompressed public key (last 20 bytes).

