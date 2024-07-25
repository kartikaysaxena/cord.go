package config

import (
	"fmt"

	gsrpc "github.com/kartikaysaxena/substrateinterface"
)

func Connect(networkAddress string, configs ConfigOpts) (*gsrpc.SubstrateAPI, error) {

	substrate, err := gsrpc.NewSubstrateAPI(networkAddress)
	fmt.Println("SubstrateAPI", substrate)
	if err != nil {
		panic(err)
	}

	configs.API = substrate
	configs.Key = "api"
	// InitAPI(configs)

	return substrate, nil
}

func Disconnect() bool {
	return IsSet("api")
}
