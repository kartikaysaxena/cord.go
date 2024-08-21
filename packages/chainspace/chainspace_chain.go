package chainspace

import (
	"github.com/centrifuge/go-substrate-rpc-client/signature"
	utils "github.com/kartikaysaxena/cord.go/packages/utils/src"
	gsrpc "github.com/kartikaysaxena/substrateinterface"
	types "github.com/kartikaysaxena/substrateinterface/types"
	"github.com/kartikaysaxena/substrateinterface/types/codec"
	did "github.com/kartikaysaxena/cord.go/packages/did"
	identifier "github.com/kartikaysaxena/cord.go/packages/identifier/src"
)

func GetURIForSpace(spaceDigest string, creatorURI string, api gsrpc.SubstrateAPI) (map[string]string, error) {

	bytes, err := codec.Encode(spaceDigest)
	if err != nil {
		panic(err)
	}
	scaleEncodedSpaceDigest, err := codec.Encode(types.NewH256(bytes))

	encodedCreator, err := codec.Encode(did.ToChain(did.DidUri(creatorURI)))
	scaleEncodedCreatorAccountID, err := types.NewAccountID(encodedCreator)
	if err != nil {
		return nil, err
	}

	scaleEncodedCreator, err := codec.Encode(scaleEncodedCreatorAccountID)

	digest := utils.Blake2AsHex(append(scaleEncodedSpaceDigest, scaleEncodedCreator[0]),256)

	chainSpaceURI := identifier.HashToURI(digest, utils.SPACE_IDENT, utils.SPACE_PREFIX)


	scaleAuthDigest := utils.InterfaceToBytes(codec.Encode(identifier.UriToIdentifier(chainSpaceURI)))

	scaleEncodedAuthDigest, err := api.EncodeScale("Bytes", identifier.UriToIdentifier(chainSpaceURI))
	if err != nil {
		return nil, err
	}

	scaleEncodedAuthDelegate, err := api.EncodeScale("AccountId", did.ToChain(creatorURI))
	if err != nil {
		return nil, err
	}

	authDigest := utils.Blake2AsHex(append(scaleEncodedAuthDigest.RemainingBytes(), scaleEncodedAuthDelegate.RemainingBytes()...))

	authorizationURI := identifier.HashToURI(authDigest, utils.AUTH_IDENT, utils.AUTH_PREFIX)

	return map[string]string{
		"uri":             chainSpaceURI,
		"authorizationURI": authorizationURI,
	}, nil
}

func SudoApproveChainSpace(authority *sdk.CordKeyringPair, spaceURI string, capacity int) error {

	spaceID := utils.URIToIdentifier(spaceURI)

	callTx, err := api.ComposeCall("ChainSpace", "approve", map[string]interface{}{
		"space_id":    spaceID,
		"txn_capacity": capacity,
	})
	if err != nil {
		return err
	}

	sudoTx, err := api.ComposeCall("Sudo", "sudo", map[string]interface{}{
		"call": callTx,
	})
	if err != nil {
		return err
	}

	extrinsic, err := api.CreateSignedExtrinsic(sudoTx, authority)
	if err != nil {
		return err
	}

	return api.SubmitExtrinsic(extrinsic, true)
}

func PrepareCreateSpaceExtrinsic(chainSpace map[string]string, creatorURI string, signCallback func(), authorAccount *sdk.CordKeyringPair) (*sdk.Extrinsic, error) {

	tx, err := api.ComposeCall("ChainSpace", "create", map[string]interface{}{
		"space_code": chainSpace["digest"],
	})
	if err != nil {
		return nil, err
	}

	extrinsic, err := Did{}.AuthorizeTx(creatorURI, tx, signCallback, authorAccount.SS58Address())
	if err != nil {
		return nil, err
	}

	return extrinsic, nil
}

func DispatchToChain(chainSpace map[string]string, creatorURI string, authorAccount *sdk.CordKeyringPair, signCallback func()) (map[string]string, error) {
	extrinsic, err := PrepareCreateSpaceExtrinsic(chainSpace, creatorURI, signCallback, authorAccount)
	if err != nil {
		return nil, err
	}

	api := ConfigService{}.GetAPI()
	extrinsic, err = api.CreateSignedExtrinsic(extrinsic, authorAccount)
	if err != nil {
		return nil, err
	}

	err = api.SubmitExtrinsic(extrinsic, true)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"uri":          chainSpace["uri"],
		"authorization": chainSpace["authorization_uri"],
	}, nil
}

func DispatchSubspaceCreateToChain(chainSpace map[string]string, creatorURI string, authorAccount *sdk.CordKeyringPair, count int, parent string, signCallback func()) (map[string]string, error) {
	api := ConfigService{}.GetAPI()

	tx, err := api.ComposeCall("ChainSpace", "subspace_create", map[string]interface{}{
		"space_code": chainSpace["digest"],
		"count":      count,
		"space_id":   utils.NullOrParent(parent),
	})
	if err != nil {
		return nil, err
	}

	extrinsic, err := Did{}.AuthorizeTx(creatorURI, tx, signCallback, authorAccount.SS58Address())
	if err != nil {
		return nil, err
	}

	extrinsic, err = api.CreateSignedExtrinsic(extrinsic, authorAccount)
	if err != nil {
		return nil, err
	}

	err = api.SubmitExtrinsic(extrinsic, true)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"uri":          chainSpace["uri"],
		"authorization": chainSpace["authorization_uri"],
	}, nil
}

func DispatchUpdateTxCapacityToChain(space string, creatorURI string, authorAccount *signature.KeyringPair, newCapacity int, signCallback func(), api *gsrpc.SubstrateAPI) (map[string]string, error) {

	tx, err := api.ComposeCall("ChainSpace", "update_transaction_capacity_sub", map[string]interface{}{
		"space_id":       utils.StripPrefix(space),
		"new_txn_capacity": newCapacity,
	})
	if err != nil {
		return nil, err
	}

	extrinsic, err := Did{}.AuthorizeTx(creatorURI, tx, signCallback, authorAccount.SS58Address())
	if err != nil {
		return nil, err
	}

	extrinsic, err = api.CreateSignedExtrinsic(extrinsic, authorAccount)
	if err != nil {
		return nil, err
	}

	err = api.SubmitExtrinsic(extrinsic, true)
	if err != nil {
		return nil, err
	}

	return map[string]string{
		"uri": space,
	}, nil
}