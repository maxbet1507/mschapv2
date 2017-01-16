package mschapv2

import "github.com/pkg/errors"

// HashNtPasswordHash implements https://tools.ietf.org/html/rfc2759#section-8.4
//
//    HashNtPasswordHash(
//    IN  16-octet PasswordHash,
//    OUT 16-octet PasswordHashHash )
//    {
//       /*
//        * Use the MD4 algorithm [5] to irreversibly hash
//        * PasswordHash into PasswordHashHash.
//        */
//    }
//
func (s *MSCHAPv2) HashNtPasswordHash(PasswordHash, PasswordHashHash []byte) {
	if s.Err != nil {
		return
	}

	s.md4reset()
	s.md4write(PasswordHash[:16])
	s.md4finish(PasswordHashHash)

	s.Err = errors.Wrap(s.Err, "HashNtPasswordHash")
}
