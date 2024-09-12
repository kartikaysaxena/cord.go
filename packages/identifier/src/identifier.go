package identifier

import (
	"errors"
	"fmt"
	"log"
	"strings"

	statement "github.com/dhiway/cord.go/packages/types/statement"
	utils "github.com/dhiway/cord.go/packages/utils/src"
)

var VALID_IDENTS = []int{
	utils.SPACE_IDENT,
	utils.SCHEMA_IDENT,
	utils.STATEMENT_IDENT,
	utils.RATING_IDENT,
	utils.AUTH_IDENT,
	utils.ACCOUNT_IDENT,
	utils.ASSET_IDENT,
	utils.ASSET_INSTANCE_IDENT,
}

var VALID_PREFIXES = []string{
	utils.SPACE_PREFIX,
	utils.SCHEMA_PREFIX,
	utils.STATEMENT_PREFIX,
	utils.RATING_PREFIX,
	utils.AUTH_PREFIX,
	utils.ACCOUNT_PREFIX,
	utils.ASSET_PREFIX,
}

var IDENT_TO_PREFIX_MAP = map[int]string{
	utils.SPACE_IDENT:          utils.SPACE_PREFIX,
	utils.SCHEMA_IDENT:         utils.SCHEMA_PREFIX,
	utils.STATEMENT_IDENT:      utils.STATEMENT_PREFIX,
	utils.RATING_IDENT:         utils.RATING_PREFIX,
	utils.AUTH_IDENT:           utils.AUTH_PREFIX,
	utils.ACCOUNT_IDENT:        utils.ACCOUNT_PREFIX,
	utils.ASSET_IDENT:          utils.ASSET_PREFIX,
	utils.ASSET_INSTANCE_IDENT: utils.ASSET_PREFIX,
}

var defaults = map[string][]int{
	"allowed_decoded_lengths": {1, 2, 4, 8, 32, 33},
	"allowed_encoded_lengths": {3, 4, 6, 10, 35, 36, 37, 38},
}

var IDFR_PREFIX = utils.StringToU8a("CRDIDFR")

func PpHash(key []byte) []byte {
	pphash, _ := utils.Blake2AsU8a(utils.U8aConcat(IDFR_PREFIX, key), 32)
	return pphash
}

func CheckIdentifierChecksum(decoded []byte) (bool, int, int, int) {
	iDfrLength := 2
	if (decoded[0] & 0b01000000) == 0 {
		iDfrLength = 1
	}

	iDfrDecoded := int(decoded[0])
	if iDfrLength == 2 {
		iDfrDecoded = (((int(decoded[0]) & 0b00111111) << 2) |
			(int(decoded[1]) >> 6) |
			((int(decoded[1]) & 0b00111111) << 8))
	}

	isContentHash := len(decoded) == 34+iDfrLength || len(decoded) == 35+iDfrLength
	length := len(decoded) - (2 - btoi(isContentHash))

	hashValue := PpHash(decoded[:length])

	isValid := (decoded[0]&0b10000000) == 0 &&
		decoded[0] != 46 &&
		decoded[0] != 47 &&
		(isContentHash && decoded[len(decoded)-2] == hashValue[0] && decoded[len(decoded)-1] == hashValue[1] ||
			decoded[len(decoded)-1] == hashValue[0])

	return isValid, length, iDfrLength, iDfrDecoded
}

func btoi(b bool) int {
	if b {
		return 1
	}
	return 0
}

func EncodeIdentifier(key interface{}, iDPrefix int) string {

	u8a, err := utils.U8aToU8a(key)
	if err != nil {
		log.Fatal(err)
	}

	utils.AssertCondition(0 <= iDPrefix && iDPrefix <= 16383 && iDPrefix != 46 && iDPrefix != 47, "Out of range IdentifierFormat specified")
	utils.AssertCondition(len(u8a) == 32 || len(u8a) == 33, "Expected a valid key to convert")

	var prefix []byte
	if iDPrefix < 64 {
		prefix = []byte{byte(iDPrefix)}
	} else {
		prefix = []byte{
			(byte((iDPrefix & 0b000011111100) >> 2)) | 0b01000000,
			byte((iDPrefix >> 8) | ((iDPrefix & 0b000000000011) << 6)),
		}
	}

	inputData := utils.U8aConcat(prefix, u8a)
	return utils.Base58Encode(utils.U8aConcat(inputData, PpHash(inputData)[:len(u8a)-1]))
}

func HashToIdentifier(digest interface{}, iDPrefix int) string {
	utils.AssertCondition(digest != nil, "Invalid digest")
	return EncodeIdentifier(digest, iDPrefix)
}

func HashToURI(digest interface{}, iDPrefix int, prefix string) string {
	utils.AssertCondition(digest != nil, "Invalid digest")
	id := EncodeIdentifier(digest, iDPrefix)
	return fmt.Sprintf("%s%s", prefix, id)
}

func HashToElementURI(digest interface{}, iDPrefix int, prefix string) string {
	utils.AssertCondition(digest != nil, "Invalid digest")
	id := EncodeIdentifier(digest, iDPrefix)
	return fmt.Sprintf("%s%s:%v", prefix, id, digest)
}

func CheckIdentifier(identifier string) (bool, string) {
	decoded, err := utils.Base58Decode(identifier)
	if err != nil {
		return false, err.Error()
	}

	isValid, _, _, idfrDecoded := CheckIdentifierChecksum(decoded)
	if idfrDecoded >= 0 && idfrDecoded <= 16383 {
		if len(decoded) != 34 && len(decoded) != 35 {
			return false, "Invalid decoded identifier length"
		}
		return isValid, ""
	}
	return false, fmt.Sprintf("Prefix mismatch, found %d", idfrDecoded)
}

func IsValidIdentifier(input string) (bool, string) { // check again
	identifier := input
	foundPrefix := false
	for _, prefix := range VALID_PREFIXES {
		if len(input) >= len(prefix) && input[:len(prefix)] == prefix {
			foundPrefix = true
			identifier = input[len(prefix):]
			break
		}
	}

	if foundPrefix {
		isValid, errMsg := CheckIdentifier(identifier)
		return isValid, errMsg
	}
	return false, "Prefix mismatch"
}

func UriToIdentifier(uri string) (string, error) {
	if uri == "" {
		return "", errors.New("URI must be a non-empty string")
	}

	var identifier string
	foundPrefix := ""
	for _, prefix := range VALID_PREFIXES {
		if strings.HasPrefix(uri, prefix) {
			foundPrefix = prefix
			break
		}
	}

	if foundPrefix != "" {
		identifier = strings.TrimPrefix(uri, foundPrefix)
	} else {
		return "", errors.New("Unknown prefix")
	}

	isValid, errorMessage := CheckIdentifier(identifier)
	if !isValid {
		return "", fmt.Errorf("%w: %s", errors.New("Invalid identifier"), errorMessage)
	}

	return identifier, nil
}

func IdentifierToUri(identifier string) (string, error) {
	if identifier == "" {
		return "", errors.New("Input must be a non-empty string")
	}

	// Check if the input is already a URI.
	for _, prefix := range VALID_PREFIXES {
		if strings.HasPrefix(identifier, prefix) {
			return identifier, nil // Return as is, since it's already a URI.
		}
	}

	// Attempt to decode the identifier and extract the prefix.
	var decoded []byte
	var err error
	var ident int

	decoded, err = utils.Base58Decode(identifier)
	if err != nil {
		return "", fmt.Errorf("Error decoding identifier: %v", err)
	}

	isValid, _, _, idfrDecoded := CheckIdentifierChecksum(decoded)
	if !isValid {
		return "", errors.New("Invalid decoded identifier checksum")
	}

	ident = idfrDecoded
	prefix, found := IDENT_TO_PREFIX_MAP[ident]
	if !found {
		return "", fmt.Errorf("Invalid or unrecognized identifier: %s", ident)
	}

	// Construct and return the URI.
	return prefix + identifier, nil
}

func GetAccountIdentifierFromAddress(address string) string {
	if strings.HasPrefix(address, utils.ACCOUNT_PREFIX) {
		return address
	}
	return utils.ACCOUNT_PREFIX + address
}

func GetAccountAddressFromIdentifier(address string) string {
	return strings.Replace(address, utils.ACCOUNT_PREFIX, "", 1)
}

func BuildStatementUri(idDigest statement.HexString, digest statement.HexString) (statement.StatementUri, error) {
	if !strings.HasPrefix(string(digest), "0x") || !strings.HasPrefix(string(idDigest), "0x") {
		return "", errors.New("digest must start with 0x")
	}
	prefix := HashToURI(idDigest, utils.STATEMENT_IDENT, utils.STATEMENT_PREFIX)
	suffix := digest[2:]

	statementUri := statement.StatementUri(fmt.Sprintf("%s:%s", prefix, suffix))
	return statementUri, nil
}

func UpdateStatementUri(stmtUri statement.StatementUri, digest statement.HexString) (statement.StatementUri, error) {
	parts := strings.Split(string(stmtUri), ":")

	if len(parts) < 3 || parts[0] != "stmt" || parts[1] != "cord" {
		return "", errors.New("invalid statementUri format")
	}

	if !strings.HasPrefix(string(digest), "0x") {
		return "", errors.New("digest must start with 0x")
	}
	suffix := string(digest)[2:]

	statementUri := statement.StatementUri(fmt.Sprintf("stmt:cord:%s:%s", parts[2], suffix))
	return statementUri, nil
}

func UriToStatementIdAndDigest(statementUri statement.StatementUri) (string, statement.StatementDigest, error) {
	parts := strings.Split(string(statementUri), ":")

	if len(parts) != 4 || parts[0] != "stmt" || parts[1] != "cord" {
		return "", "", errors.New("invalid statementUri format")
	}

	identifier := parts[2]
	suffix := parts[3]
	digest := statement.StatementDigest(fmt.Sprintf("0x%s", suffix))

	return identifier, digest, nil
}
