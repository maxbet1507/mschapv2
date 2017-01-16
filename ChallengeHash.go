package mschapv2

import "github.com/pkg/errors"

// ChallengeHash implements https://tools.ietf.org/html/rfc2759#section-8.2
//
//    ChallengeHash(
//    IN 16-octet               PeerChallenge,
//    IN 16-octet               AuthenticatorChallenge,
//    IN  0-to-256-char         UserName,
//    OUT 8-octet               Challenge
//    {
//
//       /*
//        * SHAInit(), SHAUpdate() and SHAFinal() functions are an
//        * implementation of Secure Hash Algorithm (SHA-1) [11]. These are
//        * available in public domain or can be licensed from
//        * RSA Data Security, Inc.
//        */
//
//       SHAInit(Context)
//       SHAUpdate(Context, PeerChallenge, 16)
//       SHAUpdate(Context, AuthenticatorChallenge, 16)
//
//       /*
//        * Only the user name (as presented by the peer and
//        * excluding any prepended domain name)
//        * is used as input to SHAUpdate().
//        */
//
//       SHAUpdate(Context, UserName, strlen(Username))
//       SHAFinal(Context, Digest)
//       memcpy(Challenge, Digest, 8)
//    }
//
func (s *MSCHAPv2) ChallengeHash(PeerChallenge, AuthenticatorChallenge, UserName, Challege []byte) {
	if s.Err != nil {
		return
	}

	s.sha1reset()
	s.sha1write(PeerChallenge[:16])
	s.sha1write(AuthenticatorChallenge[:16])
	s.sha1write(UserName)
	s.sha1finish(Challege)

	s.Err = errors.Wrap(s.Err, "ChallengeHash")
}
