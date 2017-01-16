package mschapv2

import "github.com/pkg/errors"

// NtPasswordHash implements https://tools.ietf.org/html/rfc2759#section-8.3
//
//    NtPasswordHash(
//    IN  0-to-256-unicode-char Password,
//    OUT 16-octet              PasswordHash )
//    {
//       /*
//        * Use the MD4 algorithm [5] to irreversibly hash Password
//        * into PasswordHash.  Only the password is hashed without
//        * including any terminating 0.
//        */
//    }
//
func (s *MSCHAPv2) NtPasswordHash(Password, PasswordHash []byte) {
	if s.Err != nil {
		return
	}

	s.md4reset()
	s.md4write(Password)
	s.md4finish(PasswordHash)

	s.Err = errors.Wrap(s.Err, "NtPasswordHash")
}
