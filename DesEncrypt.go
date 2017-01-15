package mschapv2

import (
	"crypto/des"

	"github.com/pkg/errors"
)

var (
	desParityKeyTable []byte
)

func init() {
	desParityKeyTable = makeDesParityKeyTable()
}

func makeDesParityKeyTable() []byte {
	tbl := make([]byte, 128)

	for i := uint8(0); i < 128; i++ {
		c := 0
		for j := uint(0); j < 7; j++ {
			if i&(0x01<<j) != 0 {
				c++
			}
		}

		if c%2 == 0 {
			tbl[i] = (i << 1) | 1
		} else {
			tbl[i] = (i << 1) | 0
		}
	}

	return tbl
}

func makeDesParityKey(key []byte) []byte {
	if len(key) != 7 {
		return key
	}

	pkey := []byte{
		key[0] >> 1,
		((key[0] & 0x01) << 6) | (key[1] >> 2),
		((key[1] & 0x03) << 5) | (key[2] >> 3),
		((key[2] & 0x07) << 4) | (key[3] >> 4),
		((key[3] & 0x0f) << 3) | (key[4] >> 5),
		((key[4] & 0x1f) << 2) | (key[5] >> 6),
		((key[5] & 0x3f) << 1) | (key[6] >> 7),
		key[6] & 0x7f,
	}
	for i, v := range pkey {
		pkey[i] = desParityKeyTable[v]
	}

	return pkey
}

// DesEncrypt is defined https://tools.ietf.org/html/rfc2759#section-8.6
//
//    DesEncrypt(
//    IN  8-octet Clear,
//    IN  7-octet Key,
//    OUT 8-octet Cypher )
//    {
//       /*
//        * Use the DES encryption algorithm [4] in ECB mode [10]
//        * to encrypt Clear into Cypher such that Cypher can
//        * only be decrypted back to Clear by providing Key.
//        * Note that the DES algorithm takes as input a 64-bit
//        * stream where the 8th, 16th, 24th, etc.  bits are
//        * parity bits ignored by the encrypting algorithm.
//        * Unless you write your own DES to accept 56-bit input
//        * without parity, you will need to insert the parity bits
//        * yourself.
//        */
//    }
func DesEncrypt(clear, key []byte) ([]byte, error) {
	cb, err := des.NewCipher(makeDesParityKey(key))
	if err != nil {
		return nil, errors.Wrap(err, "DesEncrypt")
	}

	out := make([]byte, des.BlockSize)
	cb.Encrypt(out, clear)

	return out, nil
}
