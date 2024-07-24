package main

import (
	"fmt"

	types "github.com/centrifuge/go-substrate-rpc-client/v4/types"
	config "github.com/kartikaysaxena/cord.go/packages/config"
	extrinsic "github.com/kartikaysaxena/cord.go/packages/types/extrinsic"
	utils "github.com/kartikaysaxena/cord.go/packages/utils/src"
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
	Pallets := meta.AsMetadataV14.Pallets
	for _, mod := range Pallets {
		fmt.Println("Module Name", mod.Name)
	}
	fmt.Println(meta.ExistsModuleMetadata("NetworkMembership"))
	fmt.Println(meta.Version)


	keyringPair, err := utils.CreateAccount()
	if err != nil {
		panic(err)
	}

	fmt.Println("keyringpair",keyringPair.URI)

	apiCall, err := utils.NewCall(meta,"NetworkMembership.nominate","NetworkMembership","nominate",keyringPair.Address,false)
	if err != nil {
		fmt.Println(err)
	}

	sudoapiCall, err := utils.NewCall(meta,"Sudo.sudo","Sudo","sudo",apiCall)


	if err != nil {
		panic(err)
	}	

	ext := extrinsic.NewExtrinsic(sudoapiCall)

	o := types.SignatureOptions{
		BlockHash:          genesisHash,
		Era:                types.ExtrinsicEra{IsMortalEra: false},
		GenesisHash:        genesisHash,
		SpecVersion:        rv.SpecVersion,
		Tip:                types.NewUCompactFromUInt(100),
		TransactionVersion: rv.TransactionVersion,
	}

	err = ext.Sign(keyringPair, o)
	if err != nil {
		panic(err)
	}
	fmt.Println("Extrinsic Signature",ext.Signature.Signature.AsSr25519)


	fmt.Println("main in sign",ext.Signature.Signature.AsSr25519)
}
