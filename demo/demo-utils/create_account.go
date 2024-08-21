package demo_utils

import (
	gsrpc "github.com/kartikaysaxena/substrateinterface"
	utils "github.com/kartikaysaxena/cord.go/packages/utils/src"
)

func AddNetworkMember(api *gsrpc.SubstrateAPI, keyringPair)  {
	// Add the account to the network
	_, err := api.RPC.Author.InsertKey(keyringPair.URI, keyringPair.PublicKey, keyringPair.Address)
	if err != nil {
		panic(err)
	}
}