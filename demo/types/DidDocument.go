package types

import (
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
)

type DidUri string

type UriFragment string

type DidResourceUri string

type KeyRelationship string

const (
	Authentication      KeyRelationship = "authentication"
	CapabilityDelegation KeyRelationship = "capabilityDelegation"
	AssertionMethod     KeyRelationship = "assertionMethod"
	KeyAgreement        KeyRelationship = "keyAgreement"
)

var keyRelationships = []KeyRelationship{
	Authentication,
	CapabilityDelegation,
	AssertionMethod,
	KeyAgreement,
}

type VerificationKeyRelationship KeyRelationship

type VerificationKeyType string

type EncryptionKeyRelationship KeyRelationship

type EncryptionKeyType string

type BaseNewDidKey struct {
	PublicKey []byte
	Type      string
}

type NewDidVerificationKey struct {
	BaseNewDidKey
	Type VerificationKeyType
}

type NewDidEncryptionKey struct {
	BaseNewDidKey
	Type EncryptionKeyType
}

type BaseDidKey struct {
	ID         UriFragment
	PublicKey  []byte
	IncludedAt types.BlockNumber
	Type       string
}

type DidVerificationKey struct {
	BaseDidKey
	Type VerificationKeyType
}

type DidEncryptionKey struct {
	BaseDidKey
	Type EncryptionKeyType
}

type DidKey interface{}

type DidServiceEndpoint struct {
	ID              UriFragment
	Type            []string
	ServiceEndpoint []string
}

type DidSignature struct {
	KeyUri    DidResourceUri
	Signature string
}

type DidDocument struct {
	Uri               DidUri
	Authentication    []DidVerificationKey
	AssertionMethod   []DidVerificationKey
	CapabilityDelegation []DidVerificationKey
	KeyAgreement      []DidEncryptionKey
	Service           []DidServiceEndpoint
}

// DidKeyRecord represents a DID key record.
type DidKeyRecord map[string]DidKey
