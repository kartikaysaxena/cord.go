package main

import (
	"fmt"

	"github.com/dhiway/cord.go/packages/config"
)

func main() {
	fmt.Println("Starting up the program")
	config.Connect("ws://127.0.0.1:9944")
}
