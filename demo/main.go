package main

import (
	"fmt"

	"github.com/ethereum/go-ethereum/common/hexutil"
	utils "github.com/dhiway/cord.go/packages/utils/src"
	gsrpc "github.com/kartikaysaxena/substrateinterface"
	"github.com/kartikaysaxena/substrateinterface/signature"
	types "github.com/kartikaysaxena/substrateinterface/types"
	"github.com/kartikaysaxena/substrateinterface/types/codec"
	"github.com/kartikaysaxena/substrateinterface/types/extrinsic"
)

const (
	AlicePubKeyHex   = "0xd43593c715fdd31c61141abd04a99fd6822c8558854ccde39a5684e7a56da27d"
	BobPubKeyHex     = "0x8eaf04151687736326c9fea17e25fc5287613693c912909cb226aa4794f26a48"
	CharliePubKeyHex = "0x90b5ab205c6974c9ea841be688864633dc9ca8a357843eeacf2314649965fe22"
)

func mustDecodeHexString(s string) []byte {
	b, err := hexutil.Decode(s)

	if err != nil {
		panic(err)
	}

	return b
}

var (
	AliceKeyRingPair = signature.KeyringPair{
		URI:       "//Alice",
		Address:   "5GrwvaEF5zXb26Fz9rcQpDWS57CtERHpNehXCPcNoHGKutQY",
		PublicKey: mustDecodeHexString(AlicePubKeyHex),
	}

	BobKeyRingPair = signature.KeyringPair{
		URI:       "//Bob",
		Address:   "5FHneW46xGXgs5mUiveU4sbTyGBzmstUspZC92UhjJM694ty",
		PublicKey: mustDecodeHexString(BobPubKeyHex),
	}

	CharlieKeyRingPair = signature.KeyringPair{
		URI:       "//Charlie",
		Address:   "5FLSigC9HGRKVhB9FiEo4Y3koPsNmBmLJbpXg2mp1hXcS59Y",
		PublicKey: mustDecodeHexString(CharliePubKeyHex),
	}
)

func main() {
	api, err := gsrpc.NewSubstrateAPI("ws://localhost:9944")

	if err != nil {
		panic(err)
	}

	meta, err := api.RPC.State.GetMetadataLatest()

	if err != nil {
		panic(err)
	}

	rv, err := api.RPC.State.GetRuntimeVersionLatest()
	if err != nil {
		panic(err)
	}

	genesisHash, err := api.RPC.Chain.GetBlockHash(0)
	if err != nil {
		panic(err)
	}

	accountStorageKey, err := types.CreateStorageKey(meta, "System", "Account", AliceKeyRingPair.PublicKey)

	if err != nil {
		panic(err)
	}

	var accountInfo types.AccountInfo
	ok, err := api.RPC.State.GetStorageLatest(accountStorageKey, &accountInfo)

	if err != nil || !ok {
		panic(err)
	}
	account, _ := utils.CreateAccount()
	fmt.Println("adress is here", account.Address, account.PublicKey, account.URI)

	call, err := types.NewCall(meta, "NetworkMembership.nominate", types.AccountID(account.PublicKey), types.Bool(false))
	if err != nil {
		panic(err)
	}

	call2, err := types.NewCall(meta, "Sudo.sudo", call)
	if err != nil {
		panic(err)
	}

	fmt.Println(call2)

	ext := extrinsic.NewExtrinsic(call2)

	err = ext.Sign(
		AliceKeyRingPair,
		meta,
		extrinsic.WithEra(types.ExtrinsicEra{IsImmortalEra: true}, genesisHash),
		extrinsic.WithNonce(types.NewUCompactFromUInt(uint64(accountInfo.Nonce))),
		extrinsic.WithTip(types.NewUCompactFromUInt(0)),
		extrinsic.WithSpecVersion(rv.SpecVersion),
		extrinsic.WithTransactionVersion(rv.TransactionVersion),
		extrinsic.WithGenesisHash(genesisHash),
	)

	if err != nil {
		panic(err)
	}

	encodedExt, err := codec.EncodeToHex(ext)

	fmt.Printf("Ext - %s\n", encodedExt)

	sub, err := api.RPC.Author.SubmitExtrinsic(ext)

	if err != nil {
		panic(err)
	}

	fmt.Println(sub)
}
