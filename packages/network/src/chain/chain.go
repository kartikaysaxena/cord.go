package network

import (
	"errors"

	extrinsic "github.com/dhiway/cord.go/packages/types/extrinsic"
	"github.com/kartikaysaxena/substrateinterface/rpc/author"
	ext "github.com/kartikaysaxena/substrateinterface/types/extrinsic"

	ConfigService "github.com/dhiway/cord.go/packages/config"
)

func SubmitSignedTx(Extrinsic ext.Extrinsic, opts ConfigService.ConfigOpts) (*author.ExtrinsicStatusSubscription, error) {

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
