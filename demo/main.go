package cord

import (
	"fmt"
	t "dhiway/cord-go/types"

	gsrpc "github.com/centrifuge/go-substrate-rpc-client/v4"
)

const (
	networkAddress = "ws://127.0.0.1:9944"	
)


func main() {

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


	keyRingPair, err := t.CordKeyPairRingFromSecret("advice curtain treat certain above asset federal cruel firm armed load two", 28)
	if err != nil {
		panic(err)
	}
	keyRingPair.ValidateAddress()
	fmt.Println(keyRingPair.URI)
	fmt.Println(keyRingPair.PublicKey)
	fmt.Println(keyRingPair.Address)
	
	// err1 := TestKeyringPairAlice.ValidateAddress()
	// if err1 != nil {
	// 	panic(err1)
	// }

}