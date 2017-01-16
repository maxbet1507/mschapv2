package mschapv2

// HashNtPasswordHash is defined https://tools.ietf.org/html/rfc2759#section-8.4
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
func (s *MSCHAPv2) HashNtPasswordHash(PasswordHash, PasswordHashHash []byte) error {
	s.md4reset()
	s.md4write(PasswordHash[:16])
	return s.md4finish(PasswordHashHash)
}
