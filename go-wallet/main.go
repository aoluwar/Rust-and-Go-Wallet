package main

import (
	"crypto/ecdsa"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	bip32 "github.com/tyler-smith/go-bip32"
	bip39 "github.com/tyler-smith/go-bip39"
)

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}

	sub := os.Args[1]
	switch sub {
	case "mnemonic":
		mnemonicCmd(os.Args[2:])
	case "keypair":
		keypairCmd(os.Args[2:])
	case "address":
		addressCmd(os.Args[2:])
	case "sign":
		signCmd(os.Args[2:])
	case "verify":
		verifyCmd(os.Args[2:])
	default:
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Println("go-wallet <command> [options]")
	fmt.Println("commands:")
	fmt.Println("  mnemonic   --words 12|15|18|21|24")
	fmt.Println("  keypair    --mnemonic <phrase> --path <m/44'/60'/0'/0/0>")
	fmt.Println("  address    --mnemonic <phrase> --path <m/44'/60'/0'/0/0>")
	fmt.Println("  sign       --mnemonic <phrase> --path <m/44'/60'/0'/0/0> --message 0xHEX")
	fmt.Println("  verify     --pubkey 0x04... --message 0xHEX --signature 0xHEX")
}

func mnemonicCmd(args []string) {
	fs := flag.NewFlagSet("mnemonic", flag.ExitOnError)
	words := fs.Int("words", 12, "word count")
	_ = fs.Parse(args)
	if !contains([]int{12, 15, 18, 21, 24}, *words) {
		fatal("invalid word count")
	}
	entropySize := map[int]int{12: 128, 15: 160, 18: 192, 21: 224, 24: 256}[*words]
	entropy, err := bip39.NewEntropy(entropySize)
	if err != nil {
		fatal(err.Error())
	}
	mn, err := bip39.NewMnemonic(entropy)
	if err != nil {
		fatal(err.Error())
	}
	fmt.Println(mn)
}

func keypairCmd(args []string) {
	fs := flag.NewFlagSet("keypair", flag.ExitOnError)
	mnemonic := fs.String("mnemonic", "", "bip39 mnemonic")
	path := fs.String("path", "m/44'/60'/0'/0/0", "derivation path")
	_ = fs.Parse(args)
	if *mnemonic == "" {
		fatal("--mnemonic required")
	}
	priv, pub, err := deriveKeypair(*mnemonic, "", *path)
	if err != nil {
		fatal(err.Error())
	}
	fmt.Printf("private: 0x%s\n", hex.EncodeToString(crypto.FromECDSA(priv)))
	fmt.Printf("public:  0x%s\n", hex.EncodeToString(crypto.FromECDSAPub(pub)))
}

func addressCmd(args []string) {
	fs := flag.NewFlagSet("address", flag.ExitOnError)
	mnemonic := fs.String("mnemonic", "", "bip39 mnemonic")
	path := fs.String("path", "m/44'/60'/0'/0/0", "derivation path")
	_ = fs.Parse(args)
	if *mnemonic == "" {
		fatal("--mnemonic required")
	}
	_, pub, err := deriveKeypair(*mnemonic, "", *path)
	if err != nil {
		fatal(err.Error())
	}
	addr := crypto.PubkeyToAddress(*pub)
	fmt.Printf("0x%s\n", strings.ToLower(addr.Hex()[2:]))
}

func signCmd(args []string) {
	fs := flag.NewFlagSet("sign", flag.ExitOnError)
	mnemonic := fs.String("mnemonic", "", "bip39 mnemonic")
	path := fs.String("path", "m/44'/60'/0'/0/0", "derivation path")
	messageHex := fs.String("message", "", "hex-encoded message bytes")
	_ = fs.Parse(args)
	if *mnemonic == "" || *messageHex == "" {
		fatal("--mnemonic and --message required")
	}
	priv, _, err := deriveKeypair(*mnemonic, "", *path)
	if err != nil {
		fatal(err.Error())
	}
	msg, err := parseHex(*messageHex)
	if err != nil {
		fatal(err.Error())
	}
	// Sign keccak256(message)
	hash := crypto.Keccak256(msg)
	sig, err := crypto.Sign(hash, priv)
	if err != nil {
		fatal(err.Error())
	}
	sig[64] += 27 // Adjust V to be 27 or 28 for Ethereum compatibility
	fmt.Printf("0x%s\n", hex.EncodeToString(sig))
}

func verifyCmd(args []string) {
	fs := flag.NewFlagSet("verify", flag.ExitOnError)
	pubHex := fs.String("pubkey", "", "hex-encoded uncompressed pubkey (65 bytes, 0x04...)")
	messageHex := fs.String("message", "", "hex-encoded message bytes")
	sigHex := fs.String("signature", "", "hex-encoded signature (65 bytes [R||S||V])")
	_ = fs.Parse(args)
	if *pubHex == "" || *messageHex == "" || *sigHex == "" {
		fatal("--pubkey, --message, --signature required")
	}
	pubBytes, err := parseHex(*pubHex)
	if err != nil {
		fatal(err.Error())
	}
	if len(pubBytes) != 65 || pubBytes[0] != 0x04 {
		fatal("pubkey must be uncompressed 65 bytes starting with 0x04")
	}
	pub, err := crypto.UnmarshalPubkey(pubBytes)
	if err != nil {
		fatal(err.Error())
	}
	msg, err := parseHex(*messageHex)
	if err != nil {
		fatal(err.Error())
	}
	sig, err := parseHex(*sigHex)
	if err != nil {
		fatal(err.Error())
	}
	hash := crypto.Keccak256(msg)
	// Recover and compare address
	recovered, err := crypto.SigToPub(hash, sig)
	if err != nil {
		fmt.Println("false")
		return
	}
	ok := recovered.X.Cmp(pub.X) == 0 && recovered.Y.Cmp(pub.Y) == 0
	if !ok {
		fmt.Println("false")
		return
	}
	fmt.Println("true")
}

func deriveKeypair(mnemonic, passphrase, path string) (*ecdsa.PrivateKey, *ecdsa.PublicKey, error) {
	if !bip39.IsMnemonicValid(mnemonic) {
		return nil, nil, errors.New("invalid mnemonic")
	}
	seed := bip39.NewSeed(mnemonic, passphrase)
	master, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, nil, err
	}
	key, err := deriveFromPath(master, path)
	if err != nil {
		return nil, nil, err
	}
	priv, err := crypto.ToECDSA(key.Key)
	if err != nil {
		return nil, nil, err
	}
	pub := &priv.PublicKey
	return priv, pub, nil
}

func deriveFromPath(master *bip32.Key, path string) (*bip32.Key, error) {
	if path == "m" || path == "M" || path == "/" {
		return master, nil
	}
	if !strings.HasPrefix(path, "m/") {
		return nil, errors.New("path must start with m/")
	}
	segments := strings.Split(path[2:], "/")
	cur := master
	for _, s := range segments {
		if s == "" {
			return nil, errors.New("empty path segment")
		}
		hardened := strings.HasSuffix(s, "'") || strings.HasSuffix(strings.ToLower(s), "h")
		if hardened {
			s = strings.TrimSuffix(strings.TrimSuffix(s, "'"), "h")
		}
		index, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("invalid index %q: %w", s, err)
		}
		if hardened {
			cur, err = cur.NewChildKey(bip32.FirstHardenedChild + uint32(index))
		} else {
			cur, err = cur.NewChildKey(uint32(index))
		}
		if err != nil {
			return nil, err
		}
	}
	return cur, nil
}

func parseHex(s string) ([]byte, error) {
	s = strings.TrimPrefix(strings.ToLower(s), "0x")
	if len(s)%2 != 0 {
		return nil, errors.New("hex length must be even")
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return b, nil
}

func contains(arr []int, v int) bool {
	for _, x := range arr {
		if x == v {
			return true
		}
	}
	return false
}

func fatal(msg string) {
	_, _ = fmt.Fprintln(os.Stderr, msg)
	os.Exit(1)
}

// Prevent unused import removal when only address is used
var _ = common.Address{}
