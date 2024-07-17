package config

import (
	"errors"
	// "reflect"

	// "fmt"
	// "strings"

	gsrpc "github.com/centrifuge/go-substrate-rpc-client"
	// "github.com/ethereum/go-ethereum/accounts/keystore"
	// "github.com/kartikaysaxena/cord.go/packages/types/extrinsic"
	subscriptionPromise "github.com/kartikaysaxena/cord.go/packages/types/subscriptionPromise"
)

// BlockchainApiMissingError represents an error for missing blockchain API configuration.
// var defaultConfig = map[string]ConfigOpts{}

var ConfigService ConfigOpts

func GetConfigField(config ConfigOpts, key string) (any, bool) {
	if key == "API" || key == "api" {
		if config.API == nil {
			return "API is empty", false
		}
		return config.API, true
	} else if key == "SubmitTxResolveOn" {
		if config.SubmitTxResolveOn == nil {
			return "SubmitTxResolveOn is empty", false
		}
		return config.SubmitTxResolveOn, true
	}
	return nil, false
}

type BlockchainApiMissingError struct{}

type ConfigOpts struct {
	API *gsrpc.SubstrateAPI

	// Storage
	SubmitTxResolveOn *subscriptionPromise.ResultEvaluator
	// ResolveOn subscriptionPromise.
	Key string
}

// var newapi,_ = gsrpc.NewSubstrateAPI("df.ds")

// var new = &ConfigOpts{
// 	API: newapi,
// 	Key: "",
// }

var configuration struct {
	ConfigOpts ConfigOpts
}

// var configuration struct {
//     ConfigOpts ConfigOpts
// }

// type RpcAPI map[string]ConfigOpts

func (e *BlockchainApiMissingError) Error() string {
	return "Blockchain API is missing. Please set the 'api' configuration."
}

// ConfigService struct managing configuration settings.

// func NewConfigOptions() *ConfigOpts {
// 	return &ConfigOpts {
// 		API: gsrpc.SubstrateAPI,
// 	}
// }
// var ConfigServiceInstance = NewConfigService()

// func NewConfigService() *ConfigService {
//     return &ConfigService{
//         config: ,
//     }
// }
// Singleton instance of ConfigService
// var once sync.Once

// Get retrieves the value of a specified configuration option.
func Get(key string) (ConfigOpts, error) {
	// ConfigServiceInstance.mu.RLock()
	// defer ConfigServiceInstance.mu.RUnlock()
	_, value := GetConfigField(ConfigService, key)
	if value == false {
		if key == "api" {
			errors.New("api missing")
		} else {
			errors.New("not configured")
		}
	}
	configuration.ConfigOpts = ConfigService
	return configuration.ConfigOpts, nil
}

// Set sets one or more configuration options.
func Set(configs ConfigOpts) {
	configuration.ConfigOpts = configs
	ConfigService = configs
}

// Unset resets a configuration option to its default value.
func Unset(key string) {
	_, val := GetConfigField(ConfigService, key)
	if val != false {
		ConfigService.Key = ""
	}
}

// IsSet checks whether a specific configuration option is set.
func IsSet(key string) bool { // revisit
	_, val := GetConfigField(ConfigService, key)
	return !val
}
