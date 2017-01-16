package mschapv2

// NtPasswordHash is defined https://tools.ietf.org/html/rfc2759#section-8.3
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
func (s *MSCHAPv2) NtPasswordHash(Password, PasswordHash []byte) error {
	s.md4reset()
	s.md4write(Password)
	return s.md4finish(PasswordHash)
}
