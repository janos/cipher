// Copyright (c) 2018 Janoš Guljaš <janos@resenje.org>
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package xor

import (
	"encoding/binary"
	"hash/adler32"

	"resenje.org/cipher"
)

var (
	_ cipher.BytesCipher  = (*Cipher)(nil)
	_ cipher.StringCipher = (*Cipher)(nil)
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
func New(key []byte, opts ...Option) (c Cipher) {
	c = Cipher{
		key:           key,
		outputEncoder: cipher.DefaultEncoder,
	}
	for _, opt := range opts {
		opt(&c)
	}
	return c
}

// EncryptString encrypts input string using XOR and Adler32 checksum
// for data validation.
func (c Cipher) EncryptString(input string) (output string, err error) {
	var b []byte
	if c.inputEncoder != nil {
		b, err = c.inputEncoder.DecodeString(input)
		if err != nil {
			return "", err
		}
	} else {
		b = []byte(input)
	}
	o, err := c.Encrypt(b)
	if err != nil {
		return "", err
	}
	return c.outputEncoder.EncodeToString(o), nil
}

// Encrypt encrypts input data using XOR and Adler32 checksum
// for data validation.
func (c Cipher) Encrypt(input []byte) ([]byte, error) {
	sum := make([]byte, adler32.Size)
	binary.BigEndian.PutUint32(sum, adler32.Checksum(input))
	return xor(append(input, sum...), c.key), nil
}

// DecryptString decrypts input string produced by EncryptString.
// It performs a basic XOR encryption and validates Adler32 checksum.
func (c Cipher) DecryptString(input string) (output string, err error) {
	b, err := c.outputEncoder.DecodeString(input)
	if err != nil {
		return "", err
	}
	o, err := c.Decrypt(b)
	if err != nil {
		return "", err
	}
	if c.inputEncoder != nil {
		output = c.inputEncoder.EncodeToString(o)
	} else {
		output = string(o)
	}
	return output, nil
}

// Decrypt decrypts input data produced by Encrypt.
// It performs a basic XOR encryption and validates Adler32 checksum.
func (c Cipher) Decrypt(input []byte) ([]byte, error) {
	dec := xor(input, c.key)
	div := len(dec) - adler32.Size
	if div <= 0 {
		return nil, cipher.ErrInvalidData
	}
	output := dec[:div]
	if binary.BigEndian.Uint32(dec[div:]) != adler32.Checksum([]byte(output)) {
		return nil, cipher.ErrInvalidData
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
