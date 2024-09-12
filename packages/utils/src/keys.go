package utils

import (
	"github.com/kartikaysaxena/substrateinterface/signature"
)

type DidKeypair struct {
	Authentication *signature.KeyringPair
	Assertion      *signature.KeyringPair
	Delegation     *signature.KeyringPair
	KeyAgreement   KeyAgreement
}

type KeyAgreement struct {
	PublicKey  [32]byte
	SecretKey [32]byte
	Type 	 string
}

func GenerateKeyAgreement(uri string) KeyAgreement{
	pub, secret := NaclBoxPairFromSecret(uri)

	return KeyAgreement{
		PublicKey:  pub,
		SecretKey: secret,
		Type: "x25519",
	}

}

func GenerateKeypairs(uri string) (DidKeypair, error) {
	if uri == "" {
		uri = GenerateMnemonic()
	}

	authentication, err := KeyPairFromURI(uri + "//did//authentication//0")
	if err != nil {
		panic(err)
	}

	assertion, err := KeyPairFromURI(uri + "//did//assertion//0")
	if err != nil {
		panic(err)
	}

	capabilityDelegation, err := KeyPairFromURI(uri + "//did//delegation//0")
	if err != nil {
		panic(err)
	}

	keyAgreement := GenerateKeyAgreement(uri + "//did//keyAgreement//0")
	return DidKeypair{
		Authentication: authentication,
		Assertion:      assertion,
		Delegation:     capabilityDelegation,
		KeyAgreement:   keyAgreement,
	}, nil

}
