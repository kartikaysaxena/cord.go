package network

import (
	"errors"

	extrinsic "github.com/kartikaysaxena/cord.go/packages/types/extrinsic"
	"github.com/kartikaysaxena/substrateinterface/rpc/author"
	"github.com/kartikaysaxena/substrateinterface/types"

	ConfigService "github.com/kartikaysaxena/cord.go/packages/config"
)

func SubmitSignedTx(Extrinsic types.Extrinsic, opts ConfigService.ConfigOpts) (*author.ExtrinsicStatusSubscription, error) {

	api, err := ConfigService.Get("api")
	if err != nil {
		return nil, errors.New("API not available")
	}

	var statusSubs *author.ExtrinsicStatusSubscription

	api.API.RPC.Author.SubmitExtrinsic(Extrinsic)
	statusSubs, err = api.API.RPC.Author.SubmitAndWatchExtrinsic(Extrinsic)
	return statusSubs, err
}

func Is_In_Block(result extrinsic.ISubmittableResult) bool {
	return result.IsInBlock
}
