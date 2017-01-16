package mschapv2

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestHashNtPasswordHash(t *testing.T) {
	// https://tools.ietf.org/html/rfc2759#section-9.2

	// 16-octet PasswordHash:
	PasswordHash, _ := hex.DecodeString("44EBBA8D5312B8D611474411F56989AE")

	// 16-octet PasswordHashHash:
	PasswordHashHash, _ := hex.DecodeString("41C00C584BD2D91C4017A2A12FA59F3F")

	m := New()
	ret := make([]byte, 16)

	if m.HashNtPasswordHash(PasswordHash, ret); m.Err != nil {
		t.Fatal(m.Err)
	}
	if !reflect.DeepEqual(ret, PasswordHashHash) {
		t.Fatal(hex.EncodeToString(ret), hex.EncodeToString(PasswordHashHash))
	}
}
