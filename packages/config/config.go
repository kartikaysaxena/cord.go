package config

import (
	"fmt"
	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
)

// func Init(config map[string]*subscriptionPromise.ResultEvaluator) {

// 	Set(config)
// }

// func InitAPI(config map[string]*ConfigOpts) {
// 	SetAPI(config)
// }

// func SetAPI(config map[string]*ConfigOpts)

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
