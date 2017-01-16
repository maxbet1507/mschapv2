package mschapv2

import (
	"encoding/hex"
	"testing"
)

func TestCheckAuthenticatorResponse(t *testing.T) {
	// https://tools.ietf.org/html/rfc2759#section-9.2

	// 0-to-256-unicode-char Password:
	Password, _ := hex.DecodeString("63006C00690065006E0074005000610073007300")

	// 24 octet NT-Response:
	NtResponse, _ := hex.DecodeString("82309ECD8D708B5EA08FAA3981CD83544233114A3D85D6DF")

	// 16-octet PeerChallenge:
	PeerChallenge, _ := hex.DecodeString("21402324255E262A28295F2B3A337C7E")

	// 16-octet AuthenticatorChallenge:
	AuthenticatorChallenge, _ := hex.DecodeString("5B5D7C7D7B3F2F3E3C2C602132262628")

	// 0-to-256-char UserName:
	UserName, _ := hex.DecodeString("55736572")

	// 42-octet AuthenticatorResponse:
	AuthenticatorResponse := []byte("S=407A5589115FD0D6209F510FE9C04566932CDA56")

	m := New()

	if err := m.CheckAuthenticatorResponse(Password, NtResponse, PeerChallenge, AuthenticatorChallenge, UserName, AuthenticatorResponse); err != nil {
		t.Fatal(err)
	}
}
