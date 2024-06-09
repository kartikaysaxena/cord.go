package config

import (
	"fmt"
	// t "github.com/centrifuge/go-substrate-rpc-client/types" 
	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
)

var cs = NewConfigService()

func Init(configs map[string]interface{},cs *ConfigService) {

	cs.Set(configs)
	// Config service would now be initiated by passing the config options
}

func Connect(networkAddress string, apiOptions ...interface{}) (*gsrpc.SubstrateAPI, error) {
	
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

	Init(map[string]interface{}{"api": *substrate},cs)
	fmt.Println("hey from here")
	return substrate, nil
}

func Disconnect() bool {
	if !cs.IsSet("api") {
		return false
	}
	cs.Unset("api")
	// api, err := cs.Get("api") 
	// if err != nil {
	// 	panic(err)
	// }
	// api.Disconnect()
	return true
}
