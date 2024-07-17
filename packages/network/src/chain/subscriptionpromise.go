package network

import (
	"errors"
	"time"
)

type Errors struct{}

func (e *Errors) TimeoutError() error {
	// rpc.
	return errors.New("Timeout error")
}

type SubscriptionOptions struct {
	ResolveOn func(interface{}) bool
	RejectOn  func(interface{}) bool
	Timeout   time.Duration
}

type Promise struct {
	Result interface{}
	Error  error
	Done   chan struct{}
}

func NewPromise() *Promise {
	return &Promise{Done: make(chan struct{})}
}

func (p *Promise) Resolve(result interface{}) {
	p.Result = result
	close(p.Done)
}

func (p *Promise) Reject(err error) {
	p.Error = err
	close(p.Done)
}

func MakeSubscriptionPromise(terminationOptions SubscriptionOptions) (*Promise, func(interface{})) {
	promise := NewPromise()

	subscription := func(value interface{}) {
		if terminationOptions.RejectOn != nil && terminationOptions.RejectOn(value) {
			if promise.Error == nil && promise.Result == nil {
				promise.Reject(errors.New("rejected"))
			}
		} else if terminationOptions.ResolveOn != nil && terminationOptions.ResolveOn(value) {
			if promise.Error == nil && promise.Result == nil {
				promise.Resolve(value)
			}
		}
	}

	if terminationOptions.Timeout > 0 {
		go func() {
			select {
			case <-time.After(terminationOptions.Timeout):
				if promise.Error == nil && promise.Result == nil {
					promise.Reject((&Errors{}).TimeoutError())
				}
			case <-promise.Done:
			}
		}()
	}

	return promise, subscription
}

func MakeSubscriptionPromiseMulti(args []SubscriptionOptions) ([]*Promise, func(interface{})) {
	var promises []*Promise
	var subscriptions []func(interface{})

	for _, options := range args {
		promise, subscription := MakeSubscriptionPromise(options)
		promises = append(promises, promise)
		subscriptions = append(subscriptions, subscription)
	}

	subscription := func(value interface{}) {
		for _, sub := range subscriptions {
			sub(value)
		}
	}

	return promises, subscription
}
