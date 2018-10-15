// Copyright (c) 2018 Janoš Guljaš <janos@resenje.org>
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xor

import (
	"encoding/base32"
	"encoding/binary"
	"errors"
	"hash/adler32"
)

// Encoding is a Base32 encoding with "0123456789abcdefghjkmnpqrstvwxyz"
// charset and without padding. It is used to encode data returned by
// EncryptString.
var Encoding = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

// Cipher defines resenje.org/cipher.StringCipher interface.
type Cipher struct {
	key []byte
}

// New returns a new Cipher instance with a given key.
func New(key []byte) (c Cipher) {
	return Cipher{
		key: key,
	}
}

// EncryptString encrypts input string using XOR and Adler32 checksum
// for data validation.
func (c Cipher) EncryptString(input string) (output string, err error) {
	sum := make([]byte, adler32.Size)
	binary.BigEndian.PutUint32(sum, adler32.Checksum([]byte(input)))
	return Encoding.EncodeToString(xor(append([]byte(input), sum...), c.key)), nil
}

// DecryptString decrypts input string produced by EncryptString.
// It performs a basic XOR encryption and validates Adler32 checksum.
func (c Cipher) DecryptString(input string) (output string, err error) {
	b, err := Encoding.DecodeString(input)
	if err != nil {
		return "", err
	}
	dec := xor(b, c.key)
	output = string(dec[:len(dec)-adler32.Size])
	if binary.BigEndian.Uint32(dec[len(dec)-adler32.Size:]) != adler32.Checksum([]byte(output)) {
		return "", errors.New("invalid checksum")
	}
	return output, nil
}

func xor(input, key []byte) (output []byte) {
	output = make([]byte, len(input))
	for i := 0; i < len(input); i++ {
		output[i] = input[i] ^ key[i%len(key)]
	}
	return output
}
