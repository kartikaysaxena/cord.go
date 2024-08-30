package subscriptionPromise

import (
	"github.com/dhiway/cord.go/packages/types/extrinsic"
)

type Evaluator[T any] func(value T) bool

type TerminationOptions[T any] struct {
	ResolveOn Evaluator[T]
	RejectOn  Evaluator[T]
	Timeout   *int // Pointer to int to represent optional value.
}

type ResultEvaluator func(value extrinsic.ISubmittableResult) bool

type ErrorEvaluator func(value error) bool

type Options TerminationOptions[extrinsic.ISubmittableResult]
