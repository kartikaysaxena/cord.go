package utils

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log"

	"strconv"

	"github.com/cosmos/go-bip39"
	"github.com/kartikaysaxena/substrateinterface/signature"
	"github.com/kartikaysaxena/substrateinterface/types"
	"github.com/mr-tron/base58/base58"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/nacl/box"
)


func CheckAddress(address string, expectedPrefix byte) bool {
	decoded, err := base58.Decode(address)
	if err != nil {
		return false
	}
	if len(decoded) == 0 {
		return false
	}

	if decoded[0] != expectedPrefix {
		return false
	}

	addressWithoutChecksum := decoded[:len(decoded)-2]
	checksum := decoded[len(decoded)-2:]

	hash := blake2b.Sum512(addressWithoutChecksum)
	calculatedChecksum := hash[:2]

	return string(checksum) == string(calculatedChecksum)
}

func U8aToHex(value []byte, bitLength int, isPrefixed bool) string {
	var prefix string
	if isPrefixed {
		prefix = "0x"
	}

	if len(value) == 0 {
		return prefix
	}
	if bitLength > 0 {
		length := (bitLength + 7) / 8 // Equivalent to Math.ceil(bitLength / 8)
		if len(value) > length {
			return fmt.Sprintf("%s%s...%s", prefix, hex.EncodeToString(value[:length/2]), hex.EncodeToString(value[len(value)-length/2:]))
		}
	}

	return fmt.Sprintf("%s%s", prefix, hex.EncodeToString(value))
}

func MakeEncryptionKeypairFromSeed(seed []byte) (map[string]interface{}, error) {
    var publicKey, privateKey *[32]byte
    var err error

    if seed == nil {
        // Generate a random seed
        seed = make([]byte, 32)
        if _, err = io.ReadFull(rand.Reader, seed); err != nil {
            return nil, err
        }
        publicKey, privateKey, err = box.GenerateKey(rand.Reader)
        if err != nil {
            return nil, err
        }
    } else {
        // Use the provided seed to create a key pair
        var privateKeyArray [32]byte
        copy(privateKeyArray[:], seed)
        privateKey = &privateKeyArray
        publicKey, _, err = box.GenerateKey(rand.Reader)
		if err != nil {
			panic(err)
		}
    }

    keypair := map[string]interface{}{
        "publicKey":  publicKey[:],
        "privateKey": privateKey[:],
        "cryptoType": "X25519",
    }

    return keypair, nil
}

func Blake2AsHex(data []byte, digestSize int) string {
	hash := blake2b.Sum256(data)
	return hex.EncodeToString(hash[:digestSize])
}

func KeyPairFromURI(uri string) (*signature.KeyringPair, error) {
	keypair, err := signature.KeyringPairFromSecret(uri, Ss58Format)
	if err != nil {
		panic(err)
	}
	return &keypair, nil
}

func Blake2AsU8a(data []byte, digestSize int) ([]byte, error) {
    hasher, err := blake2b.New(digestSize, nil)
    if err != nil {
        return nil, err
    }

    // Write data to the hasher
    _, err = hasher.Write(data)
    if err != nil {
        return nil, err
    }

    // Compute and return the digest
    return hasher.Sum(nil), nil
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

func RandomAsU8a(length int) []byte {
	b := make([]byte, length)
	rand.Read(b)
	return b
}

func GenerateMnemonic() string {
	entropy, _ := bip39.NewEntropy(256)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	return mnemonic
}

func SignatureVerify(message []byte, sig []byte, publicKey []byte) bool {
	flag, _ := signature.Verify(message, sig, string(publicKey))
	return flag
}

func decodeAddress(key string) ([]byte, error) {
    return base58.Decode(key)
}

// sshash simulates a hashing function, here using SHA256 for demonstration
func sshash(data []byte) []byte {
    hash := sha256.Sum256(data)
    return hash[:]
}

// u8aConcat concatenates multiple byte slices

func EncodeAddress(key []byte, ss58Format int) CordAddress {


    var input []byte
    if ss58Format < 64 {
        input = []byte{byte(ss58Format)}
    } else {
        input = []byte{
            byte(((ss58Format & 252) >> 2) | 64),
            byte((ss58Format >> 8) | ((ss58Format & 3) << 6)),
        }
    }

    concatenated := u8aConcat(input, key)
    hash := sshash(concatenated)

    var checksum []byte
    if len(key) == 32 || len(key) == 33 {
        checksum = hash[:2]
    } else {
        checksum = hash[:1]
    }

    finalInput := u8aConcat(concatenated, checksum)
    encoded := base58.Encode(finalInput)
    return CordAddress(encoded)
}

// func naclBoxPairFromSecret(secret []byte) (*[32]byte, *[32]byte, error) {

// 	// Hash the secret to ensure it's the correct length
// 	hashedSecret := sha256.Sum256(secret)

// 	// Generate the key pair from the hashed secret
// 	var secretKey [32]byte
// 	copy(secretKey[:], hashedSecret[:])

// 	publicKey, _, err := box.GenerateKey(rand.Reader)
// 	if err != nil {
// 		panic(err)
// 	}

// 	return publicKey, &secretKey, nil
// }

// func makeEncryptionKeypairFromSecret(secret []byte) (map[string]interface{}, error) {
// }

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
	return signature.KeyringPairFromSecret(mnemonic, 29)
}

func CreateAccount() (signature.KeyringPair, error) {
	entropy, _ := bip39.NewEntropy(256)
	mnemonic, _ := bip39.NewMnemonic(entropy)
	return signature.KeyringPairFromSecret(mnemonic, Ss58Format)
}

func InterfaceToBytes(data []byte, err error) []byte {
	return types.NewBytes(data)
}

func blake2asU8a(input string) *[32]byte {
    hash := blake2b.Sum256([]byte(input))
    var output [32]byte
    copy(output[:], hash[:32])
    return &output
}

func NaclBoxPairFromSecret(secretKey string) ([32]byte, [32]byte) {
	secretkey := blake2asU8a(secretKey)
    var publicKey [32]byte
    curve25519.ScalarBaseMult(&publicKey, secretkey)
    return publicKey, *secretkey
}
