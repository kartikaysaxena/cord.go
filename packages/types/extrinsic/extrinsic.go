package extrinsic

import (
	types "github.com/centrifuge/go-substrate-rpc-client/v4/types"
)

func NewExtrinsic(c types.Call) types.Extrinsic {
	return types.Extrinsic{
		Version: types.ExtrinsicVersion4,
		Method:  c,
	}
}

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

type CallParams struct {
	Authority string `json:"authority"`
	Expires bool `json:"expires"`
	Call types.Call `json:"call"`
}

type CallParamsv2 struct {
	CallModule string `json:"call_module"`
	CallFunction string `json:"call_function"`
	CallParams CallParams `json:"call_params"`
}

func NewCallParams(callModule string,callFunction string ,authority string, expires bool) *CallParamsv2 {

	callParams := CallParams{
		Authority: authority,
		Expires: expires,
	}

	return &CallParamsv2{
		CallModule: callModule,
		CallFunction: callFunction,
		CallParams: callParams,
	}
}

func NewCallWithSudoParams(callModule string,callFunction string, call types.Call) *CallParamsv2{
	return &CallParamsv2{
		CallModule: callModule,
		CallFunction: callFunction,
		CallParams: CallParams{
			Call: call,
		},
	}
}

// func NewCall(m *types.Metadata, call string, args []byte) (types.Call, error) {
	
// }
