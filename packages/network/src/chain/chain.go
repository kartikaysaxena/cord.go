package network

import (
	// "context"
	"errors"
	// "fmt"
	// "time"

	"github.com/centrifuge/go-substrate-rpc-client/rpc/author"
	"github.com/centrifuge/go-substrate-rpc-client/types"

	// "github.com/centrifuge/go-substrate-rpc-client/v4/signature"
	ConfigService "github.com/kartikaysaxena/cord.go/packages/config"
	// errorhandler "github.com/kartikaysaxena/cord.go/packages/network/src/errorhandler"
	// "github.com/kartikaysaxena/cord.go/packages/types/extrinsic"
)

func SubmitSignedTx(Extrinsic types.Extrinsic, opts ConfigService.ConfigOpts) (*author.ExtrinsicStatusSubscription, error) {
	// resolveOn := opts.SubmitTxResolveOn
	// if resolveOn == nil {
	// 	resolveOn = DefaultResolveOn()
	// }

	// rejectOn := opts["rejectOn"]
	// if rejectOn == nil {
	// 	rejectOn = func(result interface{}) bool {
	// 		return false
	// 	}
	// }

	// var args interface{}
	// var ctx context.Context
	api, err := ConfigService.Get("api")
	if err != nil {
		return nil, errors.New("API not available")
	}

	// Extrinsic.

	//  clientSubscription *rpc.ClientSubscription
	// clientSubscription, err := api.API.Client.Subscribe(ctx, "", "", "", "", ConfigService.ConfigService.API, args) in subscription promis

	var statusSubs *author.ExtrinsicStatusSubscription
	// promise, _ := api.API.RPC.Chain.SubscribeNewHeads()
	// promise.
	api.API.RPC.Author.SubmitExtrinsic(Extrinsic)
	statusSubs, err = api.API.RPC.Author.SubmitAndWatchExtrinsic(Extrinsic)
	// statusSubs
	return statusSubs, err
}

// func SignAndSubmitTx(Extrinsic types.Extrinsic, opts ConfigService.ConfigOpts)  {
// 	signature.KeyringPairFromSecret()
// 	// signatureOptions := &types.SignatureOptions{
// 	// 	Era:,
// 	// }
// }
