// Copyright (c) 2018 Janoš Guljaš <janos@resenje.org>
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aes

import (
	"crypto/aes"
	gocipher "crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"hash/adler32"
	"io"

	"resenje.org/cipher"
)

// Cipher defines resenje.org/cipher.StringCipher interface.
type Cipher struct {
	key           []byte
	inputEncoder  cipher.StringEncoder
	outputEncoder cipher.StringEncoder
}

// Option is used to specify optional parameters to the New constructor.
type Option func(*Cipher)

// WithOutputEncoder sets the EncryptString returned data encoding.
// By default, resenje.org/cipher.DefaultEncoder is used.
func WithOutputEncoder(e cipher.StringEncoder) Option {
	return func(c *Cipher) {
		c.outputEncoder = e
	}
}

// WithInputEncoder sets the EncryptString input data encoding.
// By default, no input data decoding of input data is performed.
// If the input data is always with the same encoding,
// encrypted strings can be reduced in size, buy specifying
// this option.
func WithInputEncoder(e cipher.StringEncoder) Option {
	return func(c *Cipher) {
		c.inputEncoder = e
	}
}

// New returns a new Cipher instance with a given key.
// The key argument should be the AES key, either 16, 24, or 32 bytes
// to select AES-128, AES-192, or AES-256.
func New(key []byte, opts ...Option) (c Cipher) {
	l := len(key)
	if l > 32 {
		l = 32
	} else if l > 24 {
		l = 24
	} else if l > 16 {
		l = 16
	}
	c = Cipher{
		key:           key[:l],
		outputEncoder: cipher.DefaultEncoder,
	}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}

// EncryptString encrypts input string using AES encryption and
// Adler32 checksum for data validation.
func (c Cipher) EncryptString(input string) (output string, err error) {
	var b []byte
	if c.inputEncoder != nil {
		b, err = c.inputEncoder.DecodeString(input)
		if err != nil {
			return "", err
		}
		input = string(b)
	} else {
		b = []byte(input)
	}

	sum := make([]byte, adler32.Size)
	binary.BigEndian.PutUint32(sum, adler32.Checksum(b))

	data := append(b, sum...)

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", fmt.Errorf("aes new cipher: %v", err)
	}

	ciphertext := make([]byte, aes.BlockSize+len(data))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", fmt.Errorf("io read full: %v", err)
	}

	gocipher.NewCFBEncrypter(block, iv).XORKeyStream(ciphertext[aes.BlockSize:], data)
	return c.outputEncoder.EncodeToString(ciphertext), nil
}

// DecryptString decrypts input string produced by EncryptString.
// It performs AES encryption and validates Adler32 checksum.
func (c Cipher) DecryptString(input string) (output string, err error) {
	ciphertext, err := c.outputEncoder.DecodeString(input)
	if err != nil {
		return "", fmt.Errorf("decode: %v", err)
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return "", fmt.Errorf("new cipher: %s", err)
	}

	if len(ciphertext) < aes.BlockSize {
		return "", cipher.ErrInvalidData
	}
	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	gocipher.NewCFBDecrypter(block, iv).XORKeyStream(ciphertext, ciphertext)

	o := ciphertext[:len(ciphertext)-adler32.Size]
	if binary.BigEndian.Uint32(ciphertext[len(ciphertext)-adler32.Size:]) != adler32.Checksum(o) {
		return "", cipher.ErrInvalidData
	}
	if c.inputEncoder != nil {
		output = c.inputEncoder.EncodeToString(o)
	} else {
		output = string(o)
	}
	return output, nil
}
