package extrinsic

import (
	types "github.com/centrifuge/go-substrate-rpc-client/types"
)

type Event struct {
	Section string
	Method  string
}

type EventDetails struct {
	Event Event
}

// func main() {
// 	types
// }

type ISubmittableResult struct {
	IsInBlock      bool
	Status         ExtrinsicStatus
	IsFinalized    bool
	IsError        bool
	InternalError  error
	Events         []EventDetails
	DispactchError *types.DispatchError
}

type AnyNumber interface{}

type ExtrinsicStatus struct {
	IsReady bool
}
