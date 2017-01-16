package mschapv2

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestChallengeResponse(t *testing.T) {
	// https://tools.ietf.org/html/rfc2759#section-9.2

	// 8-octet Challenge:
	Challege, _ := hex.DecodeString("D02E4386BCE91226")

	// 16-octet PasswordHash:
	PasswordHash, _ := hex.DecodeString("44EBBA8D5312B8D611474411F56989AE")

	// 24 octet NT-Response:
	NtResponse, _ := hex.DecodeString("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF")

	m := New()
	ret := make([]byte, 24)

	if m.ChallengeResponse(Challege, PasswordHash, ret); m.Err != nil {
		t.Fatal(m.Err)
	}
	if !reflect.DeepEqual(ret, NtResponse) {
		t.Fatal(hex.EncodeToString(ret), hex.EncodeToString(NtResponse))
	}
}
