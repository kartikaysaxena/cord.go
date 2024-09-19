package did

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/url"
	"regexp"
	"strings"

	gsrpc "github.com/kartikaysaxena/substrateinterface"
	"github.com/kartikaysaxena/substrateinterface/signature"
	"github.com/kartikaysaxena/substrateinterface/types"
	"github.com/kartikaysaxena/substrateinterface/types/codec"
	"github.com/kartikaysaxena/substrateinterface/types/extrinsic"
	ext "github.com/kartikaysaxena/substrateinterface/types/extrinsic"
	"github.com/kartikaysaxena/substrateinterface/scale"
	registry "github.com/kartikaysaxena/substrateinterface/registry"

	crypto_utils "github.com/dhiway/cord.go/packages/utils/src"
)

type TxInput struct {
	Key DidVerificationKey
}

type ApiInput struct {

	Did crypto_utils.CordAddress
	Submitter crypto_utils.CordAddress
	MaxNewAgreementKeys
	DidEndpoint []ChainEndpoint
}

type MaxNewAgreementKeys struct {
	AssertionKey crypto_utils.EncodedVerificationKey
	NewDelegationKey crypto_utils.EncodedVerificationKey
	NewAgreementKey crypto_utils.EncodedEncryptionKey	
}

type DidCall struct {
	Details []uint8
	EncodedSignature EncodedSignature
}

type AgreementKey struct {
	URI map[string]string
	Address map[string]string
	PublicKey map[string]string
}

type ChainEndpoint struct{
	Id string
	ServiceTypes []string
	Urls []string
}

type EncodedSignature struct {
	Sr25519 []uint8   `json:"sr25519"`
}

// didServiceEndpoint = []DidServiceEndpoint{
// 	Id:               "#my-service",
// 	Type:             []string{"service-type"},
// 	ServiceEndpoint: []string{"https://www.example.com"},
// }

type DidServiceEndpoint struct {
	Id               string
	Type             []string
	ServiceEndpoint  []string
}

type AgreementKeyBase struct {
	s *signature.KeyringPair
}

type EncodedSig struct {
	Data ApiInput
	KeyRelationship string
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
		return errors.New("the service ID should not contain the full DID URI, only the fragment after the '#'")
	}

	if !IsUriFragment(ResourceIDToChain(id)) {
		return errors.New("the service ID is not a valid URI fragment")
	}

	for _, uri := range serviceEndpoint {
		if !IsUri(uri) {
			return errors.New("the service uri is not valid according to RFC#3986")
		}
	}
	return nil
}

type PalletDidServiceEndpointsDidEndpoint struct {
	Id               string
	ServiceTypes 	[]string
	Urls            []string
}


func ServiceToChain(service DidServiceEndpoint) ChainEndpoint {
	return ChainEndpoint{
		Id: service.Id,
		ServiceTypes: service.Type,
		Urls: service.ServiceEndpoint,
	}
}


func PublicKeyToChain(key crypto_utils.KeyAgreement) crypto_utils.EncodedEncryptionKey {
	return crypto_utils.EncodedEncryptionKey{
		X25519: key.PublicKey,
	}
}

func GetStoreTx(api *gsrpc.SubstrateAPI, input map[string]interface{}, submitter signature.KeyringPair, signCallback func([]byte) map[string]interface{}) (ext.Extrinsic, error) {

	authentication := input["authentication"]
	fmt.Println("hmm")
	assertionMethod := input["assertion_method"]
	capabilityDelegation := input["capability_delegation"]
	keyAgreement := input["key_agreement"].(crypto_utils.KeyAgreement)
	fmt.Println(keyAgreement, "debug level keyAgreement")

	service := input["service"].([]DidServiceEndpoint)

	did := GetAddressByKey(*authentication.(*signature.KeyringPair))
	sub := GetAddressByKey(submitter)
	fmt.Println(authentication, "debug level authenticationKey")
	fmt.Println(did, "debug level did")
	fmt.Println(sub, "debug level submitter")
	newAssertionKey := DidPublicKeyDetailsFromChain(*assertionMethod.(*signature.KeyringPair))
	newDelegationKey := DidPublicKeyDetailsFromChain(*capabilityDelegation.(*signature.KeyringPair))
	newKeyAgreementKeys := PublicKeyToChain(keyAgreement)

	newServiceDetails := make([]ChainEndpoint, len(service))
	for i, svc := range service {
		newServiceDetails[i] = ServiceToChain(svc)
	}
	apiInput := ApiInput{
		Did: did,
		Submitter: sub,
		MaxNewAgreementKeys: MaxNewAgreementKeys{
			AssertionKey: newAssertionKey,
			NewDelegationKey: newDelegationKey,
			NewAgreementKey: newKeyAgreementKeys,
		},
		DidEndpoint: newServiceDetails,
		// AssertionKey: newAssertionKey,
		// NewDelegationKey: newDelegationKey,
		// NewAgreementKey: newKeyAgreementKeys,
		// NewServiceDetails: newServiceDetails,
	}
	fmt.Println(did, "debug level did")
	fmt.Println(sub, "debug level submitter")
	fmt.Println(newAssertionKey, "debug level AssertionKey")
	fmt.Println(newDelegationKey, "debug level DelegationKey")
	fmt.Println(newKeyAgreementKeys, "debug level KeyAgreementKeys")
	fmt.Println(newServiceDetails, "debug level ServiceDetails")
	fmt.Println(apiInput, "debug level apiInput")

	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		panic(err)
	}

	reg := registry.NewFactory()
	callReg, err := reg.CreateCallRegistry(meta)
	if err != nil {
		panic(err)
	}

	callIndex, err := meta.AsMetadataV14.FindCallIndex("Did.create")
	if err != nil {
		panic(err)
	}

	fmt.Println(callReg[callIndex], "debug level callReg")

	for _, fields := range callReg[callIndex].Fields {
		fmt.Println(fields.LookupIndex, "debug level fields")
		fmt.Println(meta.AsMetadataV14.EfficientLookup[fields.LookupIndex], "debug level EfficientLookup")

		for _, typeCheck := range meta.AsMetadataV14.EfficientLookup[fields.LookupIndex].Params {
			fmt.Println(typeCheck.HasType, typeCheck.Type.Int64(), "debug level typeCheck")
			fmt.Println(meta.AsMetadataV14.EfficientLookup[typeCheck.Type.Int64()], "debug level typeCheck type")




			if len(meta.AsMetadataV14.EfficientLookup[typeCheck.Type.Int64()].Params) > 0  {
				for _, typeCheck := range meta.AsMetadataV14.EfficientLookup[typeCheck.Type.Int64()].Params {
					fmt.Println(typeCheck.HasType, typeCheck.Type.Int64(), "debug level typeCheckLooped")
					fmt.Println(meta.AsMetadataV14.EfficientLookup[typeCheck.Type.Int64()], "debug level typeCheck typeLooped")
				}
			}
		}

		for _, customType := range meta.AsMetadataV14.EfficientLookup[fields.LookupIndex].Def.Variant.Variants {
			fmt.Println(customType, "debug level customType")
		}
		// customType := meta.AsMetadataV14.EfficientLookup[fields.LookupIndex].Def.Variant.Variants
	}

	// meta.AsMetadataV14.EfficientLookup[]

	// typesReg := meta.AsMetadataV14.EfficientLookup[]

	// time.Sleep(30 * time.Second)
	fmt.Println("timeout")

	byteEncoded, err := codec.Encode(EncodedSig{
		Data: apiInput,
		KeyRelationship: "authentication",
	})
	if err != nil {
		panic(err)
	}
	encoded, err := codec.Encode(apiInput)
	if err != nil {
		panic(err)
	}

	sig, err := signature.Sign(byteEncoded, authentication.(*signature.KeyringPair).URI)
	if err != nil {
		panic(err)
	}

	sign := signCallback(sig)

	encodedSignature := EncodedSignature{}

	if sig, ok := sign["signature"].([]uint8); ok {
		encodedSignature.Sr25519 = sig
	} else {
		fmt.Println("Failed to assert type to []uint8")
	}
	fmt.Println(encodedSignature.Sr25519, "sr25519 here")


	fmt.Println(encodedSignature, "debug level EncodedSignature") // 64 bytes fine

	fmt.Println(encoded, encodedSignature, "debug level DidCall")

	encodedJson, err := json.Marshal(encodedSignature)
	if err != nil {
		panic(err)
	}

	extrinsic, err := types.NewCall(meta, "Did.create", encoded, encodedJson)
	if err != nil {
		panic(err)
	}

	didExtrinsic := ext.NewExtrinsic(extrinsic)

	accountStorageKey, err := types.CreateStorageKey(meta, "System", "Account", []byte(signature.TestKeyringPairAlice.PublicKey))
	if err != nil {
		panic(err)
	}

	var accountInfo types.AccountInfo
	ok, err := api.RPC.State.GetStorageLatest(accountStorageKey, &accountInfo)
	if err != nil || !ok {
		panic(err)
	}

	genesisHash, err := api.RPC.Chain.GetBlockHash(0)
	if err != nil {
		panic(err)
	}

	rv, err := api.RPC.State.GetRuntimeVersionLatest()
	if err != nil {
		panic(err)
	}

	err = didExtrinsic.Sign(
		submitter,
		meta,
		ext.WithEra(types.ExtrinsicEra{IsImmortalEra: true}, genesisHash),
		ext.WithNonce(types.NewUCompactFromUInt(uint64(accountInfo.Nonce))),
		ext.WithTip(types.NewUCompactFromUInt(0)),
		ext.WithSpecVersion(rv.SpecVersion),
		ext.WithTransactionVersion(rv.TransactionVersion),
		ext.WithGenesisHash(genesisHash),
	)
	if err != nil {
		panic(err)
	}

	return didExtrinsic, nil
}

const MAX_NONCE_VALUE = uint64(math.MaxUint64)

func increaseNonce(currentNonce, increment uint64) uint64 {
	if currentNonce == MAX_NONCE_VALUE {
		return increment
	}
	return currentNonce + increment
}

func getNextNonce(api *gsrpc.SubstrateAPI, address string) (uint64, error) {

	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		return 0, err
	}

	storageKey, err := types.CreateStorageKey(meta, "Did", "Did", []byte(address))
	if err != nil {
		return 0, err
	}

	var accountInfo types.AccountInfo
	_, err = api.RPC.State.GetStorageLatest(storageKey, &accountInfo)
	if err != nil {
		return 0, err
	}

	var storageKeys []types.StorageKey
	storageKeys = append(storageKeys, storageKey)

	return increaseNonce(uint64(accountInfo.Nonce), 1), nil
}

func GenerateDidAuthenticatedTransaction(api *gsrpc.SubstrateAPI, params map[string]interface{}) extrinsic.Extrinsic {

	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		panic(err)
	}

	var accountInfo types.AccountInfo
	key, err := types.CreateStorageKey(meta, "System", "Account", []byte(params["submitter"].(string)))
	if err != nil {
		panic(err)
	}

	_, err = api.RPC.State.GetStorageLatest(key, &accountInfo)
	if err != nil {
		panic(err)
	}

	didStr := fmt.Sprintf("%v", params["did"])

	input := map[string]interface{}{
		"tx_counter":   params["tx_counter"],
		"did":          ToChain(DidUri(didStr)),
		"call":         params["call"],
		"submitter":    params["submitter"],
		"block_number": accountInfo.Nonce,
	}

	sig := map[string]interface{}{
		"sign": func(data map[string]interface{}) string {
			return fmt.Sprintf("Signed data: %v", data)
		},
		"key_relationship": params["key_relationship"],
		"did":              params["did"],
	}

	call, err := types.NewCall(meta, "Did", "submit_did_call", map[string]interface{}{
		"did_call":        input,
		"submit_did_call": sig,
	})
	if err != nil {
		panic(err)
	}

	return extrinsic.NewExtrinsic(call)
}

// Creates a new DID using the provided mnemonic and service endpoints
func CreateDid(api *gsrpc.SubstrateAPI, submitterAccount signature.KeyringPair, mnemonic string, didServiceEndpoint []DidServiceEndpoint) (map[string]interface{}, error) {

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
		didServiceEndpoint = []DidServiceEndpoint{
			{
				Id:              "#my-service",
				Type:            []string{"service-type"},
				ServiceEndpoint: []string{"https://www.example.com"},
			},
		}
	}

	// Get transaction for creating the DID
	didCreationTx, err := GetStoreTx(api, map[string]interface{}{
		"authentication":        authentication,
		"key_agreement":         keyAgreement,
		"assertion_method":      assertionMethod,
		"capability_delegation": capabilityDelegation,
		"service":               didServiceEndpoint,
	}, submitterAccount, func(data []byte) map[string]interface{} {
		return map[string]interface{}{
			"signature": signCallbackSignature(data, *authentication),
			"key_type":  "sr25519",
		}
	})
	if err != nil {
		return nil, err
	}

	extrinsic, err := api.RPC.Author.SubmitAndWatchExtrinsic(didCreationTx)
	if err != nil {
		panic(err)
	}

	defer extrinsic.Unsubscribe()


	didUri, err := GetDidUriFromKey(*authentication)
	if err != nil {
		panic(err)
	}

	var result map[string]interface{}

	err = api.Client.Call(result, "DidApi.query", ToChain(didUri))
	if err != nil {
		panic(err)
	}
	document := LinkedInfoFromChain(result)
	if document == nil {
		return nil, errors.New("DID was not successfully created")
	}

	return map[string]interface{}{
		"mnemonic": theMnemonic,
		"document": document["document"],
	}, nil
}

func signCallbackSignature(data []byte, signer signature.KeyringPair) []byte {
	sig, err := signature.Sign(data, signer.URI)
	if err != nil {
		panic(err)
	}
	return sig
}

func callIndex(meta *types.Metadata, call string) types.CallIndex {
	c, err := meta.FindCallIndex(call)
	if err != nil {
		panic(err)
	}
	return c
}

func MethodMappingFunc(meta *types.Metadata) map[types.CallIndex]string {
	methodMappingCallIndex := map[types.CallIndex]string{
		callIndex(meta, "Statement"):                                  "authentication",
		callIndex(meta, "Schema"):                                     "authentication",
		callIndex(meta, "ChainSpace.add_admin_delegate"):              "capability_delegation",
		callIndex(meta, "ChainSpace.add_audit_delegate"):              "capability_delegation",
		callIndex(meta, "ChainSpace.add_delegate"):                    "capability_delegation",
		callIndex(meta, "ChainSpace.remove_delegate"):                 "capability_delegation",
		callIndex(meta, "ChainSpace.create"):                          "authentication",
		callIndex(meta, "ChainSpace.archive"):                         "authentication",
		callIndex(meta, "ChainSpace.restore"):                         "authentication",
		callIndex(meta, "ChainSpace.subspace_create"):                 "authentication",
		callIndex(meta, "ChainSpace.update_transaction_capacity_sub"): "authentication",
		callIndex(meta, "Did"):                                        "authentication",
		callIndex(meta, "Did.create"):                                 "",
		callIndex(meta, "Did.submit_did_call"):                        "",
		callIndex(meta, "DidLookup"):                                  "authentication",
		callIndex(meta, "DidName"):                                    "authentication",
		callIndex(meta, "NetworkScore"):                               "authentication",
		callIndex(meta, "Asset"):                                      "authentication",
	}
	return methodMappingCallIndex
}

func findCallSectionIndex(call string, meta types.Metadata) uint8 {
	m := meta.AsMetadataV14
	for _, mod := range m.Pallets {
		if !mod.HasCalls {
			continue
		}
		if string(mod.Name) != call {
			continue
		}
		return uint8(mod.Index)
	}
	return 0
}

func findCallMethodIndex(call string, meta types.Metadata) uint8 {
	m := meta.AsMetadataV14
	for _, mod := range m.Pallets {
		if !mod.HasCalls {
			continue
		}
		if string(mod.Name) != call {
			continue
		}
		callType := mod.Calls.Type.Int64()

		if typ, ok := m.EfficientLookup[callType]; ok {
			if len(typ.Def.Variant.Variants) > 0 {
				for _, vars := range typ.Def.Variant.Variants {
					if string(vars.Name) == call {
						return uint8(vars.Index)
					}
				}
			}
		}
	}
	return 0
}

func getKeyRelationshipForMethod(call extrinsic.Extrinsic, meta types.Metadata) string {
	utilityIndex := findCallSectionIndex("utility", meta)
	batchIndex := findCallMethodIndex("batch", meta)
	batchAllIndex := findCallMethodIndex("batchAll", meta)
	forceBatchIndex := findCallMethodIndex("forceBatch", meta)

	if call.Method.CallIndex.SectionIndex == utilityIndex &&
		(call.Method.CallIndex.MethodIndex == batchIndex ||
			call.Method.CallIndex.MethodIndex == batchAllIndex ||
			call.Method.CallIndex.MethodIndex == forceBatchIndex) {

		var subCalls []extrinsic.Extrinsic

		decoder := scale.NewDecoder(bytes.NewReader(call.Method.Args))
		err := decoder.Decode(&subCalls)
		if err != nil {
			fmt.Println("Error decoding Args[0]:", err)
			return ""
		}

		var keyRelationships []string
		for _, subCall := range subCalls {
			relationship := getKeyRelationshipForMethod(subCall, meta)
			keyRelationships = append(keyRelationships, relationship)
		}

		if len(keyRelationships) > 0 {
			firstRelationship := keyRelationships[0]
			allSame := true
			for _, keyRelationship := range keyRelationships {
				if keyRelationship != firstRelationship {
					allSame = false
					break
				}
			}
			if allSame {
				return firstRelationship
			}
		}

		return ""
	}
	return ""
}

func AuthorizeTx(api *gsrpc.SubstrateAPI, creatorURI string, ext extrinsic.Extrinsic, signcallback func(), address string, signingOptions ...interface{}) (extrinsic.Extrinsic, error) {

	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		panic(err)
	}

	keyRelationship := getKeyRelationshipForMethod(ext, *meta)

	tx_counter, err := getNextNonce(api, address)
	if err != nil {
		panic(err)
	}

	didAuth := GenerateDidAuthenticatedTransaction(api, map[string]interface{}{
		"did":              creatorURI,
		"key_relationship": keyRelationship,
		"sign":             signcallback,
		"call":             ext,
		"tx_counter":       tx_counter,
		"submitter":        address,
	})
	return didAuth, nil

}
