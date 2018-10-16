// Copyright (c) 2018 Janoš Guljaš <janos@resenje.org>
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"hash/adler32"
	"io"

	rcipher "resenje.org/cipher"
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
// The key argument should be the AES key, either 16, 24, or 32 bytes
// to select AES-128, AES-192, or AES-256.
func New(key []byte) (c Cipher) {
	l := len(key)
	if l > 32 {
		l = 32
	} else if l > 24 {
		l = 24
	} else if l > 16 {
		l = 16
	}
	return Cipher{
		key: key[:l],
	}
}

// EncryptString encrypts input string using AES encryption and
// Adler32 checksum for data validation.
func (c Cipher) EncryptString(input string) (output string, err error) {
	sum := make([]byte, adler32.Size)
	binary.BigEndian.PutUint32(sum, adler32.Checksum([]byte(input)))

	data := append([]byte(input), sum...)

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", fmt.Errorf("aes new cipher: %v", err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("io read full: %v", err)
	}

	cipher.NewCFBEncrypter(block, iv).XORKeyStream(ciphertext[aes.BlockSize:], data)
	return Encoding.EncodeToString(ciphertext), nil
}

// DecryptString decrypts input string produced by EncryptString.
// It performs AES encryption and validates Adler32 checksum.
func (c Cipher) DecryptString(input string) (output string, err error) {
	ciphertext, err := Encoding.DecodeString(input)
	if err != nil {
		return "", fmt.Errorf("decode: %v", err)
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", fmt.Errorf("new cipher: %s", err)
	}

	if len(ciphertext) < aes.BlockSize {
		return "", rcipher.ErrInvalidData
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	cipher.NewCFBDecrypter(block, iv).XORKeyStream(ciphertext, ciphertext)

	o := ciphertext[:len(ciphertext)-adler32.Size]
	if binary.BigEndian.Uint32(ciphertext[len(ciphertext)-adler32.Size:]) != adler32.Checksum(o) {
		return "", rcipher.ErrInvalidData
	}
	return string(o), nil
}
