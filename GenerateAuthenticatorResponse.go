package mschapv2

import (
	"encoding/hex"
	"strings"
)

// GenerateAuthenticatorResponse is defined https://tools.ietf.org/html/rfc2759#section-8.7
//
//    GenerateAuthenticatorResponse(
//    IN  0-to-256-unicode-char Password,
//    IN  24-octet              NT-Response,
//    IN  16-octet              PeerChallenge,
//    IN  16-octet              AuthenticatorChallenge,
//    IN  0-to-256-char         UserName,
//    OUT 42-octet              AuthenticatorResponse )
//    {
//       16-octet              PasswordHash
//       16-octet              PasswordHashHash
//       8-octet               Challenge
//
//       /*
//        * "Magic" constants used in response generation
//        */
//
//       Magic1[39] =
//          {0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
//           0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
//           0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
//           0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74};
//
//       Magic2[41] =
//          {0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
//           0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
//           0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
//           0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
//           0x6E};
//
//       /*
//        * Hash the password with MD4
//        */
//
//       NtPasswordHash( Password, giving PasswordHash )
//
//       /*
//        * Now hash the hash
//        */
//
//       HashNtPasswordHash( PasswordHash, giving PasswordHashHash)
//
//       SHAInit(Context)
//       SHAUpdate(Context, PasswordHashHash, 16)
//       SHAUpdate(Context, NTResponse, 24)
//       SHAUpdate(Context, Magic1, 39)
//       SHAFinal(Context, Digest)
//
//       ChallengeHash( PeerChallenge, AuthenticatorChallenge, UserName,
//                      giving Challenge)
//
//       SHAInit(Context)
//       SHAUpdate(Context, Digest, 20)
//       SHAUpdate(Context, Challenge, 8)
//       SHAUpdate(Context, Magic2, 41)
//       SHAFinal(Context, Digest)
//
//       /*
//        * Encode the value of 'Digest' as "S=" followed by
//        * 40 ASCII hexadecimal digits and return it in
//        * AuthenticatorResponse.
//        * For example,
//        *   "S=0123456789ABCDEF0123456789ABCDEF01234567"
//        */
//
//    }
//
func (s *MSCHAPv2) GenerateAuthenticatorResponse(Password, NtResponse, PeerChallenge, AuthenticatorChallenge, UserName, AuthenticatorResponse []byte) error {
	PasswordHash := make([]byte, 16)
	PasswordHashHash := make([]byte, 16)
	Digest := make([]byte, 20)
	Challenge := make([]byte, 8)

	if err := s.NtPasswordHash(Password, PasswordHash); err != nil {
		return err
	}

	if err := s.HashNtPasswordHash(PasswordHash, PasswordHashHash); err != nil {
		return err
	}

	s.sha1reset()
	s.sha1write(PasswordHashHash)
	s.sha1write(NtResponse[:24])
	s.sha1write(magic1)
	if err := s.sha1finish(Digest); err != nil {
		return err
	}

	if err := s.ChallengeHash(PeerChallenge, AuthenticatorChallenge, UserName, Challenge); err != nil {
		return err
	}

	s.sha1reset()
	s.sha1write(Digest)
	s.sha1write(Challenge)
	s.sha1write(magic2)
	if err := s.sha1finish(Digest); err != nil {
		return err
	}

	copy(AuthenticatorResponse, []byte(strings.ToUpper("S="+hex.EncodeToString(Digest))))
	return nil
}

var (
	magic1 = []byte{
		0x4D, 0x61, 0x67, 0x69, 0x63, 0x20, 0x73, 0x65, 0x72, 0x76,
		0x65, 0x72, 0x20, 0x74, 0x6F, 0x20, 0x63, 0x6C, 0x69, 0x65,
		0x6E, 0x74, 0x20, 0x73, 0x69, 0x67, 0x6E, 0x69, 0x6E, 0x67,
		0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74, 0x61, 0x6E, 0x74,
	}

	magic2 = []byte{
		0x50, 0x61, 0x64, 0x20, 0x74, 0x6F, 0x20, 0x6D, 0x61, 0x6B,
		0x65, 0x20, 0x69, 0x74, 0x20, 0x64, 0x6F, 0x20, 0x6D, 0x6F,
		0x72, 0x65, 0x20, 0x74, 0x68, 0x61, 0x6E, 0x20, 0x6F, 0x6E,
		0x65, 0x20, 0x69, 0x74, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6F,
		0x6E,
	}
)
