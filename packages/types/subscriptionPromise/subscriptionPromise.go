package subscriptionPromise

import (
	"github.com/kartikaysaxena/cord.go/packages/types/extrinsic"
	// gsrpc "github.com/centrifuge/go-substrate-rpc-client/"
)

// type SubscriptionPromiseEvaluator map[string]Evaluator[extrinsic.ISubmittableResult]

//	type RpcAPI struct {
//	    SubscriptionPromiseEvaluator
//	    gsrpc.SubstrateAPI
//	}
//
// Evaluator is a function type that determines whether a new incoming value should reject or resolve the promise.
type Evaluator[T any] func(value T) bool

// TerminationOptions provides criteria for terminating the subscription promise.
type TerminationOptions[T any] struct {
	ResolveOn Evaluator[T]
	RejectOn  Evaluator[T]
	Timeout   *int // Pointer to int to represent optional value.
}

// ResultEvaluator is an evaluator for ISubmittableResult.
type ResultEvaluator func(value extrinsic.ISubmittableResult) bool

// ErrorEvaluator is an evaluator for error.
type ErrorEvaluator func(value error) bool

// Options are termination options for ISubmittableResult.
type Options TerminationOptions[extrinsic.ISubmittableResult]
