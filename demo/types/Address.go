package types

import (
	"errors"
	"fmt"
	"regexp"
	"github.com/centrifuge/go-substrate-rpc-client/v4/signature"
)

type Prefix uint8

type HexString string

type CordEncryptionKeypair struct {
	SecretKey []byte
	PublicKey []byte
	Type      string
}

type CordAddress string

type CordKeyPairRing signature.KeyringPair

func CordKeyPairRingFromSecret(seedOrPhrase string, network uint16) (CordKeyPairRing, error) {
	key, err := signature.KeyringPairFromSecret(seedOrPhrase, network)
	if err != nil {
		return CordKeyPairRing{}, err
	}

	return CordKeyPairRing(key), nil
}

func (c *CordKeyPairRing) ValidateAddress() error {
	if !regexp.MustCompile(`^3`).MatchString(c.Address) {
		return errors.New("address must start with '3'")
	}
	fmt.Println("Address is valid")
	return nil
}

func EncodeAddress(key []byte, ss58Format Prefix) (string, error) {
	if ss58Format == 29 {
		addr := fmt.Sprintf("3%s", key)
		if addr[0] != '3' {
			return "", errors.New("invalid CORD address format")
		}
		return addr, nil
	}
	return fmt.Sprintf("%x", key), nil
}

func EncodeCordAddress(key []byte) (CordAddress, error) {
	addr, err := EncodeAddress(key, 29)
	if err != nil {
		return "", err
	}
	return CordAddress(addr), nil
}
