package network

import (
	"errors"

	"github.com/centrifuge/go-substrate-rpc-client/v4/rpc/author"
	"github.com/centrifuge/go-substrate-rpc-client/v4/types"
	extrinsic "github.com/kartikaysaxena/cord.go/packages/types/extrinsic"

	// "github.com/centrifuge/go-substrate-rpc-client/v4/signature"
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

func Is_In_Block(result extrinsic.ISubmittableResult) (bool) {
	return result.IsInBlock
}

// func SignAndSubmitTx(Extrinsic types.Extrinsic, opts ConfigService.ConfigOpts)  {
// 	signature.KeyringPairFromSecret()
// 	// signatureOptions := &types.SignatureOptions{
// 	// 	Era:,
// 	// }
// }
