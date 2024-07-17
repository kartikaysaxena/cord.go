package config

import (
	"fmt"
	// t "github.com/centrifuge/go-substrate-rpc-client/types"
	gsrpc "github.com/centrifuge/go-substrate-rpc-client"
	// "github.com/kartikaysaxena/cord.go/packages/types/extrinsic"
	// subscriptionPromise "github.com/kartikaysaxena/cord.go/packages/types/subscriptionPromise"
)

// type RpcApI struct {
// 	SubstrateAPI gsrpc.SubstrateAPI
// 	Configs      map[string]subscriptionPromise.Evaluator[extrinsic.ISubmittableResult]
// }

func Init(configs ConfigOpts) {

	Set(configs)
	// Config service would now be initiated by passing the config options
}

func Connect(networkAddress string, configs ConfigOpts) (*gsrpc.SubstrateAPI, error) {

	substrate, err := gsrpc.NewSubstrateAPI(networkAddress)
	fmt.Println(substrate)
	fmt.Println(&substrate)
	if err != nil {
		panic(err)
	}
	nodeName, err := substrate.RPC.System.Name()
	if err != nil {
		panic(err)
	}
	nodeVersion, err := substrate.RPC.System.Version()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Connected to chain using %v v%v\n", nodeName, nodeVersion)

	// rpcAPI := &ConfigOpts{
	// 	Configs:      configs,
	// 	SubstrateAPI: *substrate,
	// }
	configs.API = substrate
	configs.Key = "api"
	Init(configs)
	fmt.Println("hey from here")

	return substrate, nil
}

func Disconnect() bool {
	return IsSet("api")
}
