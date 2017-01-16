package mschapv2

import (
	"reflect"

	"github.com/pkg/errors"
)

// CheckAuthenticatorResponse implements https://tools.ietf.org/html/rfc2759#section-8.8
//
//    CheckAuthenticatorResponse(
//    IN  0-to-256-unicode-char Password,
//    IN  24-octet              NtResponse,
//    IN  16-octet              PeerChallenge,
//    IN  16-octet              AuthenticatorChallenge,
//    IN  0-to-256-char         UserName,
//    IN  42-octet              ReceivedResponse,
//    OUT Boolean               ResponseOK )
//    {
//
//       20-octet MyResponse
//
//       set ResponseOK = FALSE
//       GenerateAuthenticatorResponse( Password, NtResponse, PeerChallenge,
//                                      AuthenticatorChallenge, UserName,
//                                      giving MyResponse)
//
//       if (MyResponse = ReceivedResponse) then set ResponseOK = TRUE
//       return ResponseOK
//    }
//
func (s *MSCHAPv2) CheckAuthenticatorResponse(Password, NtResponse, PeerChallenge, AuthenticatorChallenge, UserName, ReceivedResponse []byte) bool {
	if s.Err != nil {
		return false
	}
	MyResponse := make([]byte, 42)

	s.GenerateAuthenticatorResponse(Password, NtResponse, PeerChallenge, AuthenticatorChallenge, UserName, MyResponse)

	s.Err = errors.Wrap(s.Err, "CheckAuthenticatorResponse")
	return reflect.DeepEqual(MyResponse, ReceivedResponse)
}
