// Copyright (c) 2018 Janoš Guljaš <janos@resenje.org>
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cipher

import "errors"

// StringCipher defines methods that need to be defined
// to have a convenient way to encrypt and decrypt
// arbitrary strings.
type StringCipher interface {
	EncryptString(string) (string, error)
	DecryptString(string) (string, error)
}

// ErrInvalidData should be returned by DecryptString
// if the data validation fails.
var ErrInvalidData = errors.New("invalid data")
