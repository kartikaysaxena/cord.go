package did

import (
	"encoding/hex"
	"errors"
	"net/url"
	"regexp"
	"strings"

	gsrpc "github.com/kartikaysaxena/substrateinterface"
	ext "github.com/kartikaysaxena/substrateinterface/types/extrinsic"
	"github.com/kartikaysaxena/substrateinterface/types"
	"github.com/kartikaysaxena/substrateinterface/types/codec"

	crypto_utils "github.com/kartikaysaxena/cord.go/packages/utils/src"
)

type TxInput struct {
	Key DidVerificationKey

}

var cryptoTypeMap = map[int]string{
	0: "Ed25519",
	1: "Sr25519",
	2: "Ecdsa",
}

func ToChain(didUri DidUri) string {
	parsed, err := Parse(string(didUri))
	if err != nil {
		panic(err)
	}
	return parsed["address"].(string)
}

func ResourceIDToChain(id string) string {
	return strings.TrimPrefix(id, "#")
}

func IsUri(input string) bool {
	_, err := url.ParseRequestURI(input)
	return err == nil
}

var UriFragmentRegex = regexp.MustCompile(`^[a-zA-Z0-9._~%+,;=*()'&$!@:/?-]+$`)

func IsUriFragment(input string) bool {
	return UriFragmentRegex.MatchString(input)
}

func ValidateService(endpoint map[string]interface{}) error {
	id := endpoint["id"].(string)
	serviceEndpoint := endpoint["service_endpoint"].([]string)

	if strings.HasPrefix(id, "did:cord") {
		return errors.New("The service ID should not contain the full DID URI, only the fragment after the '#'")
	}

	if !IsUriFragment(ResourceIDToChain(id)) {
		return errors.New("The service ID is not a valid URI fragment")
	}

	for _, uri := range serviceEndpoint {
		if !IsUri(uri) {
			return errors.New("The service URI is not valid according to RFC#3986")
		}
	}
	return nil
}

func ServiceToChain(service map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{
		"id":           ResourceIDToChain(service["id"].(string)),
		"serviceTypes": service["type"].([]string),
		"urls":         service["service_endpoint"].([]string),
	}
}

func PublicKeyToChain(key map[string]interface{}) map[string]string {
	cryptoType := cryptoTypeMap[key["crypto_type"].(int)]
	publicKey := hex.EncodeToString(key["public_key"].([]byte))
	return map[string]string{cryptoType: "0x" + publicKey}
}

func GetStoreTx( api *gsrpc.SubstrateAPI, input map[string]interface{}, submitter string, signCallback func([]byte) map[string]string) (ext.DynamicExtrinsic, error) {

	authentication := input["authentication"].(DidVerificationKey)
	assertionMethod := input["assertion_method"]
	capabilityDelegation := input["capability_delegation"]
	keyAgreement := input["key_agreement"].([]map[string]interface{})
	service := input["service"].([]map[string]interface{})

	did, err := GetAddressByKey(authentication)
	if err != nil {
		panic(err)
	}

	newAssertionKey := DidPublicKeyDetailsFromChain(assertionMethod.(map[string]interface{}))
	newDelegationKey := DidPublicKeyDetailsFromChain(capabilityDelegation.(map[string]interface{}))
	newKeyAgreementKeys := make([]map[string]string, len(keyAgreement))
	for i, key := range keyAgreement {
		newKeyAgreementKeys[i] = PublicKeyToChain(key)
	}
	newServiceDetails := make([]map[string]interface{}, len(service))
	for i, svc := range service {
		newServiceDetails[i] = ServiceToChain(svc)
	}

	apiInput := map[string]interface{}{
		"did":                 did,
		"submitter":           submitter,
		"new_assertion_key":   newAssertionKey,
		"new_delegation_key":  newDelegationKey,
		"new_key_agreement_keys": newKeyAgreementKeys,
		"new_service_details": newServiceDetails,
	}

	byteEncoded, err := codec.Encode(apiInput)
	if err != nil {
		panic(err)
	}

	signature := signCallback(byteEncoded)
	encodedSignature := map[string]string{signature["key_type"]: "0x" + signature["signature"]}
	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		panic(err)
	}
	extrinsic, err := types.NewCall(meta, "Did", "create", map[string]interface{}{
		"details":   apiInput,
		"signature": encodedSignature,
	})
	
	
	return ext.NewDynamicExtrinsic(&extrinsic), nil
}

// Creates a new DID using the provided mnemonic and service endpoints
func CreateDid(api *gsrpc.SubstrateAPI , submitterAccount string, mnemonic string, didServiceEndpoint []map[string]interface{}) (map[string]interface{}, error) {

	// Generate mnemonic if not provided
	theMnemonic := mnemonic
	if theMnemonic == "" {
		theMnemonic = crypto_utils.GenerateMnemonic()
	}

	keypairs, err := crypto_utils.GenerateKeypairs(theMnemonic)
	if err != nil {
		panic(err)
	}
	authentication := keypairs.Authentication
	keyAgreement := keypairs.KeyAgreement
	assertionMethod := keypairs.Assertion
	capabilityDelegation := keypairs.Delegation

	if didServiceEndpoint == nil {
		didServiceEndpoint = []map[string]interface{}{
			{
				"id":             "#my-service",
				"type":           []string{"service-type"},
				"service_endpoint": []string{"https://www.example.com"},
			},
		}
	}

	// Get transaction for creating the DID
	didCreationTx, err := GetStoreTx(api, map[string]interface{}{
		"authentication":    authentication,
		"key_agreement":     keyAgreement,
		"assertion_method":  assertionMethod,
		"capability_delegation": capabilityDelegation,
		"service":           didServiceEndpoint,
	}, submitterAccount, func(data []byte) map[string]string {
		return map[string]string{
			"signature": "0x" + hex.EncodeToString(data),
			"key_type":  "sr25519",
		}
	})
	if err != nil {
		return nil, err
	}

	extrinsic, err := api.RPC.Author.SubmitAndWatchDynamicExtrinsic(didCreationTx)
	if err != nil {
		panic(err)
	}

	defer extrinsic.Unsubscribe()

	key := DidVerificationKey{
		PublicKey: authentication.PublicKey,
		Type: "sr25519",
	}

	didUri, err := GetDidUriFromKey(key)
	err = 	api.Client.Call("DidApi.query", ToChain(didUri))
	if err != nil {
		panic(err)
	}
	document := LinkedInfoFromChain(didServiceEndpoint[0])
	if document == nil {
		return nil, errors.New("DID was not successfully created.")
	}

	return map[string]interface{}{
		"mnemonic": theMnemonic,
		"document": document["document"],
	}, nil
}

