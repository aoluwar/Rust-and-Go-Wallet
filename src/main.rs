use anyhow::{anyhow, Result};
use clap::{Parser, Subcommand};
use rand::rngs::OsRng;

use bip39::{Language, Mnemonic};
use bip32::{XPrv, DerivationPath};
use k256::ecdsa::{SigningKey, VerifyingKey};
use secp256k1::{Message as SecpMessage, Secp256k1, ecdsa::{RecoverableSignature as SecpRecoverableSignature, RecoveryId as SecpRecoveryId}};
use tiny_keccak::{Hasher, Keccak};
use sha3::{Digest, Keccak256};

#[derive(Parser, Debug)]
#[command(name = "rust-wallet")] 
#[command(about = "Simple Rust wallet: mnemonic, key, address, sign, verify", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generate a new BIP39 mnemonic
    Mnemonic {
        /// Word count: 12, 15, 18, 21, 24
        #[arg(short, long, default_value_t = 12)]
        words: u8,
    },
    /// Derive secp256k1 keypair from mnemonic and path
    Keypair {
        /// BIP39 mnemonic phrase
        #[arg(short, long)]
        mnemonic: String,
        /// Derivation path (default m/44'/60'/0'/0/0)
        #[arg(short = 'p', long, default_value = "m/44'/60'/0'/0/0")]
        path: String,
    },
    /// Compute address (Ethereum-style keccak of uncompressed pubkey)
    Address {
        #[arg(short, long)]
        mnemonic: String,
        #[arg(short = 'p', long, default_value = "m/44'/60'/0'/0/0")]
        path: String,
    },
    /// Sign a hex message with derived key
    Sign {
        #[arg(short, long)]
        mnemonic: String,
        #[arg(short = 'p', long, default_value = "m/44'/60'/0'/0/0")]
        path: String,
        /// Hex-encoded message bytes (e.g., 0x68656c6c6f)
        #[arg(short = 'M', long)]
        message: String,
    },
    /// Verify a signature against a message and pubkey (Ethereum 65-byte [R||S||V])
    Verify {
        /// Hex-encoded verifying key (uncompressed 65 bytes, 0x04...)
        #[arg(short, long)]
        pubkey: String,
        /// Hex-encoded message
        #[arg(short, long)]
        message: String,
        /// Hex-encoded signature (65 bytes R||S||V)
        #[arg(short, long)]
        signature: String,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Mnemonic { words } => {
            let word_count = match words {
                12 | 15 | 18 | 21 | 24 => words as usize,
                _ => return Err(anyhow!("invalid word count")),
            };
            let mut rng = OsRng;
            let mnemonic = Mnemonic::generate_in_with(&mut rng, Language::English, word_count)?;
            println!("{}", mnemonic.to_string());
        }
        Commands::Keypair { mnemonic, path } => {
            let (signing, verifying) = derive_keys(&mnemonic, &path)?;
            println!("private: 0x{}", hex::encode(signing.to_bytes()));
            println!("public:  0x{}", hex::encode(verifying.to_encoded_point(false).as_bytes()));
        }
        Commands::Address { mnemonic, path } => {
            let (_, verifying) = derive_keys(&mnemonic, &path)?;
            let address = ethereum_address_from_pubkey(&verifying);
            println!("0x{}", address);
        }
        Commands::Sign { mnemonic, path, message } => {
            let (signing, _) = derive_keys(&mnemonic, &path)?;
            let msg_bytes = parse_hex(&message)?;
            let sig65 = sign_eth_65(&signing, &msg_bytes)?;
            println!("0x{}", hex::encode(sig65));
        }
        Commands::Verify { pubkey, message, signature } => {
            let vk = parse_uncompressed_pubkey(&pubkey)?;
            let msg_bytes = parse_hex(&message)?;
            let sig_bytes = parse_hex(&signature)?;
            let ok = verify_eth_65(&vk, &msg_bytes, &sig_bytes);
            println!("{}", if ok { "true" } else { "false" });
        }
    }
    Ok(())
}

fn derive_keys(mnemonic_phrase: &str, derivation_path: &str) -> Result<(SigningKey, VerifyingKey)> {
    let mnemonic: Mnemonic = mnemonic_phrase.parse()?;
    let seed_bytes = mnemonic.to_seed_normalized("");
    let xprv = XPrv::derive_from_path(&seed_bytes, &derivation_path.parse::<DerivationPath>()?)?;
    let signing_key = SigningKey::from_bytes(&xprv.private_key().to_bytes().into())?;
    let verifying_key = VerifyingKey::from(&signing_key);
    Ok((signing_key, verifying_key))
}

fn ethereum_address_from_pubkey(vk: &VerifyingKey) -> String {
    let uncompressed = vk.to_encoded_point(false);
    let pubkey_bytes = &uncompressed.as_bytes()[1..];
    let mut keccak = Keccak::v256();
    let mut out = [0u8; 32];
    keccak.update(pubkey_bytes);
    keccak.finalize(&mut out);
    hex::encode(&out[12..])
}

fn parse_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    if s.len() % 2 != 0 { return Err(anyhow!("hex length must be even")); }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i+2], 16).map_err(|e| anyhow!(e)))
        .collect()
}

fn parse_uncompressed_pubkey(s: &str) -> Result<VerifyingKey> {
    let bytes = parse_hex(s)?;
    if bytes.len() != 65 || bytes[0] != 0x04 { return Err(anyhow!("pubkey must be 65 bytes starting with 0x04")); }
    Ok(VerifyingKey::from_sec1_bytes(&bytes)?)
}

fn sign_eth_65(sk: &SigningKey, message: &[u8]) -> Result<Vec<u8>> {
    // Hash with keccak256 per Ethereum signing of raw bytes (not EIP-191 prefixing)
    let hash = Keccak256::digest(message);
    // Use secp256k1 recoverable to produce [R||S||V]
    let secp = Secp256k1::new();
    let msg = SecpMessage::from_slice(&hash)?;
    let sk_bytes = sk.to_bytes();
    let secp_sk = secp256k1::SecretKey::from_slice(&sk_bytes)?;
    let rec = secp.sign_ecdsa_recoverable(&msg, &secp_sk);
    let (rid, compact) = rec.serialize_compact();
    let mut sig65 = vec![0u8; 65];
    sig65[0..64].copy_from_slice(&compact);
    sig65[64] = 27 + rid.to_i32() as u8; // 27 or 28
    Ok(sig65)
}

// Verify a 65-byte Ethereum-style signature ([R||S||V]) against a message and public key
// Returns true if the signature is valid, false otherwise
fn verify_eth_65(vk: &VerifyingKey, message: &[u8], sig: &[u8]) -> bool {
    if sig.len() != 65 { return false; }
    let hash = Keccak256::digest(message);
    // Recover and compare
    let secp = Secp256k1::new();
    let msg = match SecpMessage::from_slice(&hash) { Ok(m) => m, Err(_) => return false };
    let v = sig[64];
    let rec_id = match SecpRecoveryId::from_i32((v as i32) - 27) { Ok(id) => id, Err(_) => return false };
    let mut compact = [0u8; 64];
    compact.copy_from_slice(&sig[0..64]);
    let rec_sig = match SecpRecoverableSignature::from_compact(&compact, rec_id) { Ok(s) => s, Err(_) => return false };
    let pk = match secp.recover_ecdsa(&msg, &rec_sig) { Ok(p) => p, Err(_) => return false };
    let uncompressed = pk.serialize_uncompressed();
    // Compare with provided verifying key
    match VerifyingKey::from_sec1_bytes(&uncompressed) {
        Ok(recovered_vk) => recovered_vk.to_encoded_point(false).as_bytes() == vk.to_encoded_point(false).as_bytes(),
        Err(_) => false,
    }
}
