package mschapv2

import (
	"crypto/sha1"
	"encoding/binary"
	"hash"

	"github.com/pkg/errors"

	"golang.org/x/crypto/md4"
)

// MSCHAPv2 implements https://tools.ietf.org/html/rfc2759
type MSCHAPv2 struct {
	Err  error
	md4  hash.Hash
	sha1 hash.Hash
}

func (s *MSCHAPv2) md4reset() {
	if s.Err != nil {
		return
	}

	s.md4.Reset()
}

func (s *MSCHAPv2) md4write(v []byte) {
	if s.Err != nil {
		return
	}

	s.Err = binary.Write(s.md4, binary.BigEndian, v)
	s.Err = errors.Wrap(s.Err, "md4.Write")
}

func (s *MSCHAPv2) md4finish(v []byte) {
	if s.Err != nil {
		return
	}

	copy(v, s.md4.Sum(nil))
}

func (s *MSCHAPv2) sha1reset() {
	if s.Err != nil {
		return
	}

	s.sha1.Reset()
}

func (s *MSCHAPv2) sha1write(v []byte) {
	if s.Err != nil {
		return
	}

	s.Err = binary.Write(s.sha1, binary.BigEndian, v)
	s.Err = errors.Wrap(s.Err, "sha1.Write")
}

func (s *MSCHAPv2) sha1finish(v []byte) {
	if s.Err != nil {
		return
	}

	copy(v, s.sha1.Sum(nil))
}

// Reset sets Err = nil
func (s *MSCHAPv2) Reset() {
	s.Err = nil
}

// New returns an initialized MSCHAPv2.
func New() *MSCHAPv2 {
	return &MSCHAPv2{
		md4:  md4.New(),
		sha1: sha1.New(),
	}
}
