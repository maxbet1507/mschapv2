package mschapv2

import (
	"crypto/sha1"
	"encoding/binary"
	"hash"

	"golang.org/x/crypto/md4"
)

// MSCHAPv2 contains hash.Hash instances.
type MSCHAPv2 struct {
	md4     hash.Hash
	md4err  error
	sha1    hash.Hash
	sha1err error
}

func (s *MSCHAPv2) md4reset() {
	s.md4err = nil
	s.md4.Reset()
}

func (s *MSCHAPv2) md4write(v []byte) {
	if s.md4err != nil {
		return
	}

	s.md4err = binary.Write(s.md4, binary.BigEndian, v)
}

func (s *MSCHAPv2) md4finish(v []byte) error {
	if s.md4err == nil {
		copy(v, s.md4.Sum(nil))
	}
	return s.md4err
}

func (s *MSCHAPv2) sha1reset() {
	s.sha1err = nil
	s.sha1.Reset()
}

func (s *MSCHAPv2) sha1write(v []byte) {
	if s.sha1err != nil {
		return
	}

	s.sha1err = binary.Write(s.sha1, binary.BigEndian, v)
}

func (s *MSCHAPv2) sha1finish(v []byte) error {
	if s.sha1err == nil {
		copy(v, s.sha1.Sum(nil))
	}
	return s.sha1err
}

// New returns an initialized MSCHAPv2.
func New() *MSCHAPv2 {
	return &MSCHAPv2{
		md4:  md4.New(),
		sha1: sha1.New(),
	}
}
