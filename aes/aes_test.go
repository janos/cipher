// Copyright (c) 2018 Janoš Guljaš <janos@resenje.org>
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aes

import (
	"math/rand"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	keyLen := 16
	key := make([]byte, 16)
	n, err := rand.Read(key)
	if err != nil {
		t.Errorf("rand.Read: %s", err)
	}
	if n != keyLen {
		t.Errorf("rand.Read: only %d bytes read out of %d", n, keyLen)
	}
	data := "testing"

	c := New(key)

	enc, err := c.EncryptString(data)
	if err != nil {
		t.Errorf("encrypt: %s", err)
	}
	dec, err := c.DecryptString(enc)
	if err != nil {
		t.Errorf("decrypt: %s", err)
	}
	if data != dec {
		t.Errorf("original and decrypted data are not equal")
	}
}
