package utils

import (
	// "crypto/rand"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"

	// "reflect"
	"strconv"

	// "github.com/cosmos/go-bip39"

	// "github.com/ChainSafe/go-schnorrkel"
	// "github.com/gtank/merlin"
	"github.com/centrifuge/go-substrate-rpc-client/signature"
	// "github.com/centrifuge/go-substrate-rpc-client//types/codec"
	"github.com/cosmos/go-bip39"
	// "github.com/kartikaysaxena/cord.go/packages/types/address"
	// "github.com/kartikaysaxena/cord.go/packages/types/statement"
	"github.com/mr-tron/base58/base58"
	"golang.org/x/crypto/blake2b"
)

// func IsString(value interface{}) bool {
// 	v := reflect.ValueOf(value)
// 	return v.Kind() == reflect.String
// }

// func StringToU8a(value interface{}) []byte {
// 	str := fmt.Sprint(value) // Convert value to string

// 	// Encode the string to []byte (UTF-8 encoding)
// 	u8a := []byte(str)

// 	return u8a
// }

// func hello() {
// 	types.keypa
// }

func U8aToHex(value []byte, bitLength int, isPrefixed bool) string {
	var prefix string
	if isPrefixed {
		prefix = "0x"
	}

	if len(value) == 0 {
		return prefix
	}
	// Handle bit length, if provided
	if bitLength > 0 {
		length := (bitLength + 7) / 8 // Equivalent to Math.ceil(bitLength / 8)
		if len(value) > length {
			return fmt.Sprintf("%s%s...%s", prefix, hex.EncodeToString(value[:length/2]), hex.EncodeToString(value[len(value)-length/2:]))
		}
	}

	return fmt.Sprintf("%s%s", prefix, hex.EncodeToString(value))
}

func Blake2AsHex(data []byte, digestSize int) string {
	hash := blake2b.Sum256(data)
	return hex.EncodeToString(hash[:digestSize])
}

func Blake2AsU8a(data []byte, bitLength int, key []byte) ([]byte, error) {
	// Convert data to []byte

	inputData := data

	// Select the BLAKE2b function based on the bit length
	var hashFunc func([]byte) ([]byte, error)
	switch bitLength {
	case 64:
		hashFunc = func(data []byte) ([]byte, error) {
			hash := blake2b.Sum512(data) // blake2b doesn't support 64 directly, using 512 for illustration
			return hash[:8], nil
		}
	case 128:
		hashFunc = func(data []byte) ([]byte, error) {
			hash := blake2b.Sum512(data) // blake2b doesn't support 128 directly, using 512 for illustration
			return hash[:16], nil
		}
	case 256:
		hashFunc = func(data []byte) ([]byte, error) {
			hash := blake2b.Sum256(data)
			return hash[:], nil
		}
	case 384:
		hashFunc = func(data []byte) ([]byte, error) {
			hash, err := blake2b.New384(key)
			if err != nil {
				return nil, err
			}
			hash.Write(data)
			return hash.Sum(nil), nil
		}
	case 512:
		hashFunc = func(data []byte) ([]byte, error) {
			hash, err := blake2b.New512(key)
			if err != nil {
				return nil, err
			}
			hash.Write(data)
			return hash.Sum(nil), nil
		}
	default:
		return nil, fmt.Errorf("unsupported bit length")
	}

	// Calculate the hash
	return hashFunc(inputData)
}

func u8aConcat(lists ...[]byte) []byte {
	var buffer bytes.Buffer
	for _, list := range lists {
		buffer.Write(list)
	}
	return buffer.Bytes()
}

func Base58Encode(data []byte) string {
	return base58.Encode(data)
}

func Base58Decode(data string) ([]byte, error) {
	return base58.Decode(data)
}

// func CheckAddress(address string, expectedPrefix byte) bool {
// 	decoded, err := Base58Decode(address)
// 	if err != nil || len(decoded) == 0 || decoded[0] != expectedPrefix {
// 		return false
// 	}
// 	return true
// }

func RandomAsU8a(length int) []byte {
	b := make([]byte, length)
	rand.Read(b)
	return b
}

func GenerateMnemonic() (string, error) {
	entropy, _ := bip39.NewEntropy(256)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	return mnemonic, nil
}

func SignatureVerify(message []byte, sig []byte, publicKey []byte) bool { // REVISTTTTT
	flag, _ := signature.Verify(message, sig, string(publicKey))
	return flag
}

func EncodeAddress(publicKey []byte, ss58Format byte) string {
	return Base58Encode(publicKey)
}

func DecodeAddress(address string) ([]byte, error) {
	return Base58Decode(address)
}

func IsHex(data string) bool {
	_, err := hex.DecodeString(data)
	return err == nil
}

func HexToBn(hexString string) (int64, error) {
	return strconv.ParseInt(hexString, 16, 64)
}

func AssertCondition(condition bool, message string) {
	if !condition {
		log.Fatal(message)
	}
}

func IsString(data interface{}) bool {
	_, ok := data.(string)
	return ok
}

func StringToU8a(s string) []byte {
	return []byte(s)
}

func U8aConcat(args ...[]byte) []byte {
	var result []byte
	for _, arg := range args {
		result = append(result, arg...)
	}
	return result
}

func U8aToString(value []byte) string {
	if len(value) == 0 {
		return ""
	}
	return string(value)
}

func U8aToU8a(data interface{}) ([]byte, error) {
	switch v := data.(type) {
	case []byte:
		return v, nil
	case string:
		if len(v) > 2 && v[:2] == "0x" {
			return hex.DecodeString(v[2:])
		}
		return StringToU8a(v), nil
	default:
		return nil, fmt.Errorf("unsupported input type for conversion to u8a")
	}
}

func CreateFromMnemonic(mnemonic string) (signature.KeyringPair, error) {
	return signature.KeyringPairFromSecret(mnemonic, "ws://127.0.0.1:9944")
}
