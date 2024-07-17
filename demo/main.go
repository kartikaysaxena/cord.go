package main

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

}

func Hello0() {
	fmt.Println("Hello0")
}