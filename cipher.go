// Copyright (c) 2018 Janoš Guljaš <janos@resenje.org>
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher

import (
	"encoding/base32"
	"errors"
)

// DefaultEncoding is a Base32 encoding with "0123456789abcdefghjkmnpqrstvwxyz"
// charset and without padding. It is used to encode data returned by
// EncryptString.
var DefaultEncoder StringEncoder = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

// BytesCipher defines methods that need to be defined
// to have a convenient way to encrypt and decrypt
// arbitrary data and strings.
type Cipher interface {
	BytesCipher
	StringCipher
}

// BytesCipher defines methods that need to be defined
// to have a convenient way to encrypt and decrypt
// arbitrary data.
type BytesCipher interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
}

// StringCipher defines methods that need to be defined
// to have a convenient way to encrypt and decrypt
// arbitrary strings.
type StringCipher interface {
	EncryptString(string) (string, error)
	DecryptString(string) (string, error)
}

// StringEncoder is used to specify encoding for input
// or output data.
type StringEncoder interface {
	EncodeToString([]byte) string
	DecodeString(string) ([]byte, error)
}

// ErrInvalidData should be returned by DecryptString
// if the data validation fails.
var ErrInvalidData = errors.New("invalid data")
