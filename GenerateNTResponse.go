package mschapv2

import "github.com/pkg/errors"

// GenerateNTResponse is defined https://tools.ietf.org/html/rfc2759#section-8.1
//
//    GenerateNTResponse(
//    IN  16-octet              AuthenticatorChallenge,
//    IN  16-octet              PeerChallenge,
//    IN  0-to-256-char         UserName,
//    IN  0-to-256-unicode-char Password,
//    OUT 24-octet              Response )
//    {
//       8-octet  Challenge
//       16-octet PasswordHash
//
//       ChallengeHash( PeerChallenge, AuthenticatorChallenge, UserName,
//                      giving Challenge)
//
//       NtPasswordHash( Password, giving PasswordHash )
//       ChallengeResponse( Challenge, PasswordHash, giving Response )
//    }
//
func (s *MSCHAPv2) GenerateNTResponse(AuthenticatorChallenge, PeerChallenge, UserName, Password, Response []byte) {
	if s.Err != nil {
		return
	}
	Challenge := make([]byte, 8)
	PasswordHash := make([]byte, 16)

	s.ChallengeHash(PeerChallenge[:16], AuthenticatorChallenge[:16], UserName, Challenge)
	s.NtPasswordHash(Password, PasswordHash)
	s.ChallengeResponse(Challenge, PasswordHash, Response)

	s.Err = errors.Wrap(s.Err, "GenerateNTResponse")
}
