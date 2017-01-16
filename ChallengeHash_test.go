package mschapv2

import "testing"
import "encoding/hex"
import "reflect"

func TestChallengeHash(t *testing.T) {
	// https://tools.ietf.org/html/rfc2759#section-9.2

	// 16-octet PeerChallenge:
	PeerChallenge, _ := hex.DecodeString("21402324255E262A28295F2B3A337C7E")

	// 16-octet AuthenticatorChallenge:
	AuthenticatorChallenge, _ := hex.DecodeString("5B5D7C7D7B3F2F3E3C2C602132262628")

	// 0-to-256-char UserName:
	UserName, _ := hex.DecodeString("55736572")

	// 8-octet Challenge:
	Challege, _ := hex.DecodeString("D02E4386BCE91226")

	m := New()
	ret := make([]byte, 8)

	if m.ChallengeHash(PeerChallenge, AuthenticatorChallenge, UserName, ret); m.Err != nil {
		t.Fatal(m.Err)
	}
	if !reflect.DeepEqual(ret, Challege) {
		t.Fatal(hex.EncodeToString(ret), hex.EncodeToString(Challege))
	}
}
