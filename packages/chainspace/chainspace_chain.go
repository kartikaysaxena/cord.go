package chainspace

import (
	"github.com/kartikaysaxena/substrateinterface/signature"
	did "github.com/kartikaysaxena/cord.go/packages/did"
	identifier "github.com/kartikaysaxena/cord.go/packages/identifier/src"
	utils "github.com/kartikaysaxena/cord.go/packages/utils/src"
	gsrpc "github.com/kartikaysaxena/substrateinterface"
	"github.com/kartikaysaxena/substrateinterface/rpc/author"
	types "github.com/kartikaysaxena/substrateinterface/types"
	"github.com/kartikaysaxena/substrateinterface/types/codec"
	"github.com/kartikaysaxena/substrateinterface/types/extrinsic"
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

	identifierToUri, err := identifier.UriToIdentifier(chainSpaceURI)
	if err != nil {
		return nil, err
	}
	scaleAuthDigest := utils.InterfaceToBytes(codec.Encode(identifierToUri))

	scaleEncodedAuthDigest := types.NewBytes(scaleAuthDigest)

	scaleEncodedAuthDelegate, err := types.NewAccountID(utils.InterfaceToBytes(codec.Encode(did.ToChain(did.DidUri(creatorURI)))))

	authDigest := utils.Blake2AsHex(append(scaleEncodedAuthDigest, scaleEncodedAuthDelegate[0]), 256)

	authorizationURI := identifier.HashToURI(authDigest, utils.AUTH_IDENT, utils.AUTH_PREFIX)

	return map[string]string{
		"uri":             chainSpaceURI,
		"authorizationURI": authorizationURI,
	}, nil
}

func SudoApproveChainSpace(authority *signature.KeyringPair, spaceURI string, capacity int, api *gsrpc.SubstrateAPI) (*author.ExtrinsicStatusSubscription,error) {

	spaceID, err := identifier.UriToIdentifier(spaceURI)
	if err != nil {
		return nil,err
	}

	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		return nil,err
	}

	callTx, err := types.NewCall(meta, "ChainSpace.approve", map[string]interface{}{
		"space_id":    spaceID,
		"txn_capacity": capacity,
	})
	if err != nil {
		return nil,err
	}

	sudoTx, err := types.NewCall(meta,"Sudo.sudo", map[string]interface{}{
		"call": callTx,
	})
	if err != nil {
		return nil,err
	}

	ext := extrinsic.NewDynamicExtrinsic(&sudoTx)
	if err != nil {
		return nil,err
	}

	return api.RPC.Author.SubmitAndWatchDynamicExtrinsic(ext)
}

func PrepareCreateSpaceExtrinsic(chainSpace map[string]string, creatorURI string, signCallback func(), authorAccount *signature.KeyringPair, api *gsrpc.SubstrateAPI) (*extrinsic.DynamicExtrinsic, error) {

	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		return nil,err
	}

	tx, err := types.NewCall(meta,"ChainSpace.create", map[string]interface{}{
		"space_code": chainSpace["digest"],
	})
	if err != nil {
		return nil, err
	}

	ext := extrinsic.NewDynamicExtrinsic(&tx)

	extrinsic, err := did.AuthorizeTx(creatorURI, ext, signCallback, authorAccount.Address, nil)
	if err != nil {
		return nil, err
	}

	return extrinsic, nil
}

func DispatchToChain(chainSpace map[string]string, creatorURI string, authorAccount *signature.KeyringPair, signCallback func(), api *gsrpc.SubstrateAPI) (map[string]string, error) {
	ext, err := PrepareCreateSpaceExtrinsic(chainSpace, creatorURI, signCallback, authorAccount, api)
	if err != nil {
		return nil, err
	}


	// extr := ext.Sign(authorAccount)

	err = ext.Sign(
		*authorAccount,
		meta,
		extrinsic.WithEra(types.ExtrinsicEra{IsImmortalEra: true}, genesisHash),
		extrinsic.WithNonce(types.NewUCompactFromUInt(uint64(accountInfo.Nonce))),
		extrinsic.WithTip(types.NewUCompactFromUInt(0)),
		extrinsic.WithSpecVersion(rv.SpecVersion),
		extrinsic.WithTransactionVersion(rv.TransactionVersion),
		extrinsic.WithGenesisHash(genesisHash),
	)
	// extrinsic, err = api.CreateSignedExtrinsic(extrinsic, authorAccount)
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