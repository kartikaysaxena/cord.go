package config

import (
	"errors"

	subscriptionPromise "github.com/kartikaysaxena/cord.go/packages/types/subscriptionPromise"
	gsrpc "github.com/kartikaysaxena/substrateinterface"
)

var ConfigService ConfigOpts

func GetConfigField(config ConfigOpts, key string) (any, bool) {
	if key == "API" || key == "api" {
		if config.API == nil {
			return "API is empty", false
		}
		return config.API, true
	} else if key == "submitTxResolveOn" {
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

	SubmitTxResolveOn *subscriptionPromise.ResultEvaluator
	Key               string
}

var configuration struct {
	ConfigOpts ConfigOpts
}

func (e *BlockchainApiMissingError) Error() string {
	return "Blockchain API is missing. Please set the 'api' configuration."
}

func Get(key string) (ConfigOpts, error) {
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

func Set(config map[string]*subscriptionPromise.ResultEvaluator) {
	for key, value := range config {
		ConfigService.Key = key
		if key == "submitTxResolveOn" {
			ConfigService.SubmitTxResolveOn = value
		}
	}
}

func Unset(key string) {
	_, val := GetConfigField(ConfigService, key)
	if val != false {
		ConfigService.Key = ""
	}
}

func IsSet(key string) bool { // revisit
	_, val := GetConfigField(ConfigService, key)
	return !val
}
