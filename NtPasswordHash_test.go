package mschapv2

import "testing"
import "encoding/hex"
import "reflect"

func TestNtPasswordHash(t *testing.T) {
	// https://tools.ietf.org/html/rfc2759#section-9.2

	// 0-to-256-unicode-char Password:
	Password, _ := hex.DecodeString("63006C00690065006E0074005000610073007300")

	// 16-octet PasswordHash:
	PasswordHash, _ := hex.DecodeString("44EBBA8D5312B8D611474411F56989AE")

	m := New()
	ret := make([]byte, 16)

	if m.NtPasswordHash(Password, ret); m.Err != nil {
		t.Fatal(m.Err)
	}
	if !reflect.DeepEqual(ret, PasswordHash) {
		t.Fatal(hex.EncodeToString(ret), hex.EncodeToString(PasswordHash))
	}
}
