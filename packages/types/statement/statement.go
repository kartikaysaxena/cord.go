package statement

import (
	"errors"
	"regexp"
	"strings"
	// "github.com/centrifuge/go-substrate-rpc-client//signature"
	// types "github.com/centrifuge/go-substrate-rpc-client//types"
	// "github.com/centrifuge/go-substrate-rpc-client//types/codec"
)

type HexString string

type StatementDigest HexString

const STATEMENT_PREFIX = "stmt:cord:"

// StatementUri is a custom type representing a statement URI with a specific prefix.
type StatementUri string

// Validate checks if the StatementUri has the correct prefix.
func (s StatementUri) Validate() error {
	if !strings.HasPrefix(string(s), STATEMENT_PREFIX) {
		return errors.New("invalid StatementUri format, must start with " + STATEMENT_PREFIX)
	}
	return nil
}

// Validate checks if the HexString has the correct format.
func (h HexString) Validate() error {
	// Regular expression to match hexadecimal string prefixed with '0x'.
	match, _ := regexp.MatchString(`^0x[0-9a-fA-F]+$`, string(h))
	if !match {
		return errors.New("invalid HexString format")
	}
	return nil
}
