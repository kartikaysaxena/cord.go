package statement

import (
	"errors"
	"regexp"
	"strings"
)

type HexString string

type StatementDigest HexString

const STATEMENT_PREFIX = "stmt:cord:"

type StatementUri string

func (s StatementUri) Validate() error {
	if !strings.HasPrefix(string(s), STATEMENT_PREFIX) {
		return errors.New("invalid StatementUri format, must start with " + STATEMENT_PREFIX)
	}
	return nil
}

func (h HexString) Validate() error {
	match, _ := regexp.MatchString(`^0x[0-9a-fA-F]+$`, string(h))
	if !match {
		return errors.New("invalid HexString format")
	}
	return nil
}
