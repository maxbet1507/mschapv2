package mschapv2

import (
	"encoding/hex"
	"reflect"
	"testing"
)

func TestDesEncrypt1(t *testing.T) {
	// https://tools.ietf.org/html/rfc2759#section-9.3

	// First "raw" DES key (initial 7 octets of password hash):
	rawDesKey, _ := hex.DecodeString("FC156AF7EDCD6C")

	// First parity-corrected DES key (eight octets):
	parityCorrectedDesKey, _ := hex.DecodeString("FD0B5B5E7F6E34D9")

	ret := makeDesParityKey(rawDesKey)
	if !reflect.DeepEqual(parityCorrectedDesKey, ret) {
		t.Fatal(hex.EncodeToString(ret), hex.EncodeToString(parityCorrectedDesKey))
	}
}

func TestDesEncrypt2(t *testing.T) {
	// https://tools.ietf.org/html/rfc2759#section-9.3

	//Second "raw" DES key (second 7 octets of password hash)
	rawDesKey, _ := hex.DecodeString("0EDDE3337D427F")

	//Second parity-corrected DES key (eight octets):
	parityCorrectedDesKey, _ := hex.DecodeString("0E6E796737EA08FE")

	ret := makeDesParityKey(rawDesKey)
	if !reflect.DeepEqual(parityCorrectedDesKey, ret) {
		t.Fatal(hex.EncodeToString(ret), hex.EncodeToString(parityCorrectedDesKey))
	}
}
