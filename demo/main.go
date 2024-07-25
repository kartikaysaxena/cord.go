package main

import (
	"fmt"

	config "github.com/kartikaysaxena/cord.go/packages/config"
	// extrinsic "github.com/kartikaysaxena/cord.go/packages/types/extrinsic"
	utils "github.com/kartikaysaxena/cord.go/packages/utils/src"
	types "github.com/kartikaysaxena/substrateinterface/types"
	ext "github.com/kartikaysaxena/substrateinterface/types/extrinsic"
	"github.com/kartikaysaxena/substrateinterface/types/extrinsic/extensions"

)

func main() {

	api, err := config.Connect("ws://127.0.0.1:9944", config.ConfigService)
	if err != nil {
		panic(err)
	}
	fmt.Println(api)
	nodeName, err := api.RPC.System.Name()
	if err != nil {
		panic(err)
	}
	nodeVersion, err := api.RPC.System.Version()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Connected to chain using with nodeName %v and nodeVersion v%v\n", nodeName, nodeVersion)

	genesisHash, err := api.RPC.Chain.GetBlockHash(0)
	if err != nil {
		panic(err)
	}
	fmt.Println("Genesis Hash", genesisHash)

	rv, err := api.RPC.State.GetRuntimeVersionLatest()
	if err != nil {
		panic(err)
	}
	fmt.Println("Runtime Version", rv)

	health, err := api.RPC.System.Health()
	if err != nil {
		panic(err)
	}
	fmt.Println("Health object", health)

	newSubscriptionHead, err := api.RPC.Chain.SubscribeNewHeads()
	if err != nil {

		panic(err)
	}
	fmt.Println("New Subscription head object", newSubscriptionHead)

	meta, err := api.RPC.State.GetMetadataLatest()
	if err != nil {
		panic(err)
	}
	fmt.Println("version")
	fmt.Println(meta.Version)
	fmt.Println(meta.ExistsModuleMetadata("NetworkMembership"))
	fmt.Println(meta.Version)

	keyringPair, err := utils.CreateAccount()
	if err != nil {
		panic(err)
	}

	fmt.Println("keyringpair", keyringPair.URI)

	call, err := types.NewCall(meta, "NetworkMembership.nominate")
	if err != nil {
		fmt.Println(err)
	}

	sudoCall, err := types.NewCall(meta, "Sudo.sudo", call)

	if err != nil {
		panic(err)
	}
	accountStorageKey, err := types.CreateStorageKey(meta, "System", "Account", keyringPair.PublicKey)
	var accountInfo types.AccountInfo
	ok, err := api.RPC.State.GetStorageLatest(accountStorageKey, &accountInfo)

	if err != nil || !ok {
		panic(err)
	}

	extr := ext.NewDynamicExtrinsic(&sudoCall)

	err = extr.Sign(
		keyringPair,
		meta,
		ext.WithEra(types.ExtrinsicEra{IsImmortalEra: true}, genesisHash),
		ext.WithNonce(types.NewUCompactFromUInt(uint64(accountInfo.Nonce))),
		ext.WithTip(types.NewUCompactFromUInt(0)),
		ext.WithSpecVersion(rv.SpecVersion),
		ext.WithTransactionVersion(rv.TransactionVersion),
		ext.WithGenesisHash(genesisHash),
		ext.WithMetadataMode(extensions.CheckMetadataModeDisabled, extensions.CheckMetadataHash{Hash: types.NewEmptyOption[types.H256]()}),
		ext.WithAssetID(types.NewEmptyOption[types.AssetID]()),
	)
	if err != nil {
		panic(err)
	}
	fmt.Println("Extrinsic Signature", extr.Signature.Signature.AsSr25519)

	fmt.Println("main in sign", extr.Signature.Signature.AsSr25519)

	sub, err := api.RPC.Author.SubmitAndWatchDynamicExtrinsic(extr)
	fmt.Println(sub)

	if err != nil {
		panic(err)
	}

	defer sub.Unsubscribe()

	for {
		select {
		case st := <-sub.Chan():
			extStatus, _ := st.MarshalJSON()
			fmt.Printf("Status for transaction - %s\n", string(extStatus))
		case err := <-sub.Err():
			panic(err)
		}
	}

}
