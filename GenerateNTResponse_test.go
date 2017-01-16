package mschapv2

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestGenerateNTResponse(t *testing.T) {
	// https://tools.ietf.org/html/rfc2759#section-9.2

	// 16-octet AuthenticatorChallenge:
	AuthenticatorChallenge, _ := hex.DecodeString("5B5D7C7D7B3F2F3E3C2C602132262628")

	// 16-octet PeerChallenge:
	PeerChallenge, _ := hex.DecodeString("21402324255E262A28295F2B3A337C7E")

	// 0-to-256-char UserName:
	UserName, _ := hex.DecodeString("55736572")

	// 0-to-256-unicode-char Password:
	Password, _ := hex.DecodeString("63006C00690065006E0074005000610073007300")

	// 24 octet NT-Response:
	NtResponse, _ := hex.DecodeString("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF")

	m := New()
	ret := make([]byte, 24)

	if err := m.GenerateNTResponse(AuthenticatorChallenge, PeerChallenge, UserName, Password, ret); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(ret, NtResponse) {
		t.Fatal(hex.EncodeToString(ret), hex.EncodeToString(NtResponse))
	}
}
