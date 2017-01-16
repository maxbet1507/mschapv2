package mschapv2

import "github.com/pkg/errors"

// ChallengeResponse implements https://tools.ietf.org/html/rfc2759#section-8.5
//
//    ChallengeResponse(
//    IN  8-octet  Challenge,
//    IN  16-octet PasswordHash,
//    OUT 24-octet Response )
//    {
//       Set ZPasswordHash to PasswordHash zero-padded to 21 octets
//
//       DesEncrypt( Challenge,
//                   1st 7-octets of ZPasswordHash,
//                   giving 1st 8-octets of Response )
//
//       DesEncrypt( Challenge,
//                   2nd 7-octets of ZPasswordHash,
//                   giving 2nd 8-octets of Response )
//
//       DesEncrypt( Challenge,
//                   3rd 7-octets of ZPasswordHash,
//                   giving 3rd 8-octets of Response )
//    }
//
func (s *MSCHAPv2) ChallengeResponse(Challenge, PasswordHash, Response []byte) {
	if s.Err != nil {
		return
	}
	ZPassword := append(PasswordHash[:16], 0x00, 0x00, 0x00, 0x00, 0x00)

	response1 := make([]byte, 8)
	s.DesEncrypt(Challenge[:8], ZPassword[0:7], response1)

	response2 := make([]byte, 8)
	s.DesEncrypt(Challenge[:8], ZPassword[7:14], response2)

	response3 := make([]byte, 8)
	s.DesEncrypt(Challenge[:8], ZPassword[14:21], response3)

	response := append(response1, response2...)
	response = append(response, response3...)
	copy(Response, response)

	s.Err = errors.Wrap(s.Err, "ChallengeResponse")
}
