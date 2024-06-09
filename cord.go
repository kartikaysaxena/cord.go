package cord

import (
	"fmt"
	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
)

const (
	networkAddress = "ws://127.0.0.1:9944"
)

func Cord() {
	api, err := gsrpc.NewSubstrateAPI(networkAddress)
	fmt.Println(api)
	if err != nil {
		panic(err)
	}
	hash, err := api.RPC.Chain.GetBlockHashLatest()
	if err != nil {
		panic(err)
	}
	fmt.Println(hash)
	nodeName, err := api.RPC.System.Name()
	if err != nil {
		panic(err)
	}
	nodeVersion, err := api.RPC.System.Version()
	if err != nil {
		panic(err)
	}
	fmt.Printf("Connected to chain using %v v%v\n", nodeName, nodeVersion)

}

func Hello() {
	fmt.Println("Hello0")
}
