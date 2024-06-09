package config

import (
	"errors"
	"fmt"
	"sync"
)

type SDKErrors struct{}

type BlockchainApiMissingError struct{}

// sdk error types to be shifted to packages/utils

func (e *BlockchainApiMissingError) Error() string {
    return "Blockchain API is missing"
}

type ConfigService struct {
    config map[string]interface{}
    mu     *sync.RWMutex
}

func NewConfigService() *ConfigService {
    return &ConfigService{
        config: make(map[string]interface{}),
    }
}

func (cs *ConfigService) Get(key string) (interface{}, error) {
    cs.mu.RLock()
    defer cs.mu.RUnlock()

    value, exists := cs.config[key]
    if !exists {
        if key == "api" {
            return nil, &BlockchainApiMissingError{}
        }
        return nil, errors.New("GENERIC NOT CONFIGURED ERROR FOR KEY: \"" + key + "\"")
    }
    return value, nil
}

func (cs *ConfigService) Set(configs map[string]interface{}) {
	fmt.Println(configs)
	cs.config = make(map[string]interface{})
    for key, value := range configs {
		fmt.Println(value)
        cs.config[key] = value
    }
}

func (cs *ConfigService) Unset(key string) {
    cs.mu.Lock()
    defer cs.mu.Unlock()
    delete(cs.config, key)
}

func (cs *ConfigService) IsSet(key string) bool {
    cs.mu.RLock()
    defer cs.mu.RUnlock()

    _, exists := cs.config[key]
    return exists
}
