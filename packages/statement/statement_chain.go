package statement

import (
	"github.com/kartikaysaxena/cord.go/packages/did"
	identifier "github.com/kartikaysaxena/cord.go/packages/identifier/src"
	utils "github.com/kartikaysaxena/cord.go/packages/utils/src"
	gsrpc "github.com/kartikaysaxena/substrateinterface"
	"github.com/kartikaysaxena/substrateinterface/signature"
	"github.com/kartikaysaxena/substrateinterface/types"
	"github.com/kartikaysaxena/substrateinterface/types/codec"
	"github.com/kartikaysaxena/substrateinterface/types/extrinsic"
)

// GetURIForStatement generates a unique URI for a statement based on its digest, space URI, and creator URI.
func GetURIForStatement(api *gsrpc.SubstrateAPI, digest []byte, spaceURI, creatorURI string) (string, error) {

	scaleEncodedSchema:= utils.InterfaceToBytes(codec.Encode(types.NewH256(digest)))

	uri, err := identifier.UriToIdentifier(spaceURI)
	if err != nil {
		return "", err
	}a

	scaleEncodedSpace := types.NewBytes(utils.InterfaceToBytes(codec.Encode(uri)))

	scaleEncodedCreator, err := types.NewAccountID(utils.InterfaceToBytes(codec.Encode(creatorURI)))
	if err != nil {
		return "", err
	}

	idDigest := "0x" + utils.CryptoUtils.Blake2AsHex(concatenatedData)

	return identifier.BuildStatementURI(idDigest, digest), nil
}

// IsStatementStored checks if a statement is stored on the CORD blockchain.
func IsStatementStored(digest, spaceURI string) (bool, error) {
	api := sdk.ConfigService.Get("api")
	space := identifier.URIToIdentifier(spaceURI)
	encoded := api.Query("Statement", "IdentifierLookup", []string{digest, space})

	if encoded.Value == nil {
		return false, nil
	}
	return true, nil
}

// PrepareExtrinsicToRegister prepares and returns a SubmittableExtrinsic for registering a statement on the blockchain.
func PrepareExtrinsicToRegister(stmtEntry map[string]string, creatorURI string, authorAccount *sdk.KeyringPair, authorizationURI string, signCallback func([]byte) ([]byte, error)) (map[string]interface{}, error) {
	api := sdk.ConfigService.Get("api")
	authorizationID := identifier.URIToIdentifier(authorizationURI)
	var schemaID string

	if schemaURI, ok := stmtEntry["schema_uri"]; ok {
		schemaID = identifier.URIToIdentifier(schemaURI)
	}

	exists, err := IsStatementStored(stmtEntry["digest"], stmtEntry["space_uri"])
	if err != nil {
		return nil, err
	}
	if exists {
		return nil, errors.New(fmt.Sprintf("The statement is already anchored in the chain\nIdentifier: %s", stmtEntry["elementUri"]))
	}

	tx := api.ComposeCall("Statement", "register", map[string]interface{}{
		"digest":       stmtEntry["digest"],
		"authorization": authorizationID,
		"schema_id":    schemaID,
	})

	extrinsic, err := sdk.Did.AuthorizeTx(creatorURI, tx, signCallback, authorAccount.SS58Address)
	if err != nil {
		return nil, err
	}

	return extrinsic, nil
}

// DispatchRegisterToChain dispatches a statement entry to the blockchain after preparing the extrinsic and signing it.
func DispatchRegisterToChain(stmtEntry map[string]string, creatorURI string, authorAccount *sdk.KeyringPair, authorizationURI string, signCallback func([]byte) ([]byte, error)) (string, error) {
	api := sdk.ConfigService.Get("api")
	extrinsic, err := PrepareExtrinsicToRegister(stmtEntry, creatorURI, authorAccount, authorizationURI, signCallback)
	if err != nil {
		return "", err
	}

	extrinsicSigned := api.CreateSignedExtrinsic(extrinsic, authorAccount)
	api.SubmitExtrinsic(extrinsicSigned, true)

	return stmtEntry["element_uri"], nil
}

// DispatchUpdateToChain dispatches a statement update transaction to the CORD blockchain.
func DispatchUpdateToChain(stmtEntry map[string]string, creatorURI string, authorAccount *sdk.KeyringPair, authorizationURI string, signCallback func([]byte) ([]byte, error)) (string, error) {
	api := sdk.ConfigService.Get("api")
	authorizationID := identifier.URIToIdentifier(authorizationURI)

	exists, err := IsStatementStored(stmtEntry["digest"], stmtEntry["space_uri"])
	if err != nil {
		return "", err
	}
	if exists {
		return stmtEntry["element_uri"], nil
	}

	stmtIDDigest := identifier.URIToStatementIDAndDigest(stmtEntry["element_uri"])

	tx := api.ComposeCall("Statement", "update", map[string]interface{}{
		"statement_id":          stmtIDDigest.Identifier,
		"new_statement_digest": stmtEntry["digest"],
		"authorization":         authorizationID,
	})

	extrinsic, err := sdk.Did.AuthorizeTx(creatorURI, tx, signCallback, authorAccount.SS58Address)
	if err != nil {
		return "", err
	}

	extrinsicSigned := api.CreateSignedExtrinsic(extrinsic, authorAccount)
	api.SubmitExtrinsic(extrinsicSigned, true)

	return stmtEntry["element_uri"], nil
}

// PrepareExtrinsicToRevoke prepares a statement revocation transaction for the CORD blockchain.
func PrepareExtrinsicToRevoke(statementURI, creatorURI string, authorAccount *sdk.KeyringPair, authorizationURI string, signCallback func([]byte) ([]byte, error)) (map[string]interface{}, error) {
	api := sdk.ConfigService.Get("api")
	authorizationID := identifier.URIToIdentifier(authorizationURI)

	stmtIDDigest := identifier.URIToStatementIDAndDigest(statementURI)
	stmtID := stmtIDDigest.Identifier

	tx := api.ComposeCall("Statement", "revoke", map[string]interface{}{
		"statement_id": stmtID,
		"authorization": authorizationID,
	})

	extrinsic, err := sdk.Did.AuthorizeTx(creatorURI, tx, signCallback, authorAccount.SS58Address)
	if err != nil {
		return nil, err
	}

	return extrinsic, nil
}

// DispatchRevokeToChain dispatches a statement revocation transaction to the blockchain.
func DispatchRevokeToChain(statementURI, creatorURI string, authorAccount *sdk.KeyringPair, authorizationURI string, signCallback func([]byte) ([]byte, error)) error {
	api := sdk.ConfigService.Get("api")
	extrinsic, err := PrepareExtrinsicToRevoke(statementURI, creatorURI, authorAccount, authorizationURI, signCallback)
	if err != nil {
		return err
	}

	extrinsicSigned := api.CreateSignedExtrinsic(extrinsic, authorAccount)
	api.SubmitExtrinsic(extrinsicSigned, true)

	return nil
}

// DispatchRestoreToChain dispatches a statement restoration transaction to the blockchain.
func DispatchRestoreToChain(statementURI, creatorURI string, authorAccount *sdk.KeyringPair, authorizationURI string, signCallback func([]byte) ([]byte, error)) error {
	api := sdk.ConfigService.Get("api")
	authorizationID := identifier.URIToIdentifier(authorizationURI)

	stmtIDDigest := identifier.URIToStatementIDAndDigest(statementURI)
	stmtID := stmtIDDigest.Identifier

	tx := api.ComposeCall("Statement", "restore", map[string]interface{}{
		"statement_id": stmtID,
		"authorization": authorizationID,
	})

	extrinsic, err := sdk.Did.AuthorizeTx(creatorURI, tx, signCallback, authorAccount.SS58Address)
	if err != nil {
		return err
	}

	extrinsicSigned := api.CreateSignedExtrinsic(extrinsic, authorAccount)
	api.SubmitExtrinsic(extrinsicSigned, true)

	return nil
}

// DecodeStatementDetailsFromChain decodes statement details from their blockchain-encoded format.
func DecodeStatementDetailsFromChain(encoded sdk.EncodedStatement, identifier string) map[string]string {
	chainStatement := encoded.Value.(map[string]interface{})
	schemaDetails, schemaPresent := chainStatement["schema"]

	var schemaURI string
	if schemaPresent && schemaDetails != nil {
		schemaURI = identifier.IdentifierToURI(schemaDetails.(string))
	}

	return map[string]string{
		"uri":       identifier.IdentifierToURI(identifier),
		"digest":    chainStatement["digest"].(string),
		"space_uri": identifier.IdentifierToURI(chainStatement["space"].(string)),
		"schema_uri": schemaURI,
	}
}

// GetDetailsFromChain retrieves detailed state information of a statement from the CORD blockchain.
func GetDetailsFromChain(identifier string) (map[string]string, error) {
	api := sdk.ConfigService.Get("api")
	statementID := identifier.URIToIdentifier(identifier)

	statementEntry := api.Query("Statement", "Statements", []string{statementID})
	if statementEntry == nil {
		return nil, errors.New(fmt.Sprintf("There is no statement with the provided ID \"%s\" present on the chain.", statementID))
	}

	decodedDetails := DecodeStatementDetailsFromChain(statementEntry, identifier)
	return decodedDetails, nil
}

// FetchStatementDetailsFromChain fetches the state of a statement element from the blockchain.
func FetchStatementDetailsFromChain(stmtURI string) (map[string]interface{}, error) {
	api := sdk.ConfigService.Get("api")
	res := identifier.URIToStatementIDAndDigest(stmtURI)
	identifier := res["identifier"]
	digest := res["digest"]

	statementDetails, err := GetDetailsFromChain(identifier)
	if err != nil {
		return nil, err
	}

	elementStatusDetails := api.Query("Statement", "Entries", []string{identifier, digest})
	if elementStatusDetails == nil {
		return nil, errors.New(fmt.Sprintf("There is no entry with the provided ID \"%s\" and digest \"%s\" present on the chain.", identifier, digest))
	}

	elementChainCreator := elementStatusDetails.Value
	elementCreator := sdk.Did.FromChain(elementChainCreator.(string))
	elementStatus := api.Query("Statement", "RevocationList", []string{identifier, digest})
	revoked := false
	if elementStatus != nil && elementStatus.Value != nil {
		encodedStatus := elementStatus.Value.(map[string]interface{})
		revoked = encodedStatus["revoked"].(bool)
	}

	return map[string]interface{}{
		"uri":        statementDetails["uri"],
		"digest":     digest,
		"space_uri":  statementDetails["space_uri"],
		"creator_uri": elementCreator,
		"schema_uri": statementDetails["schema_uri"],
		"revoked":    revoked,
	}, nil
}
