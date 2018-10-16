// Copyright (c) 2018 Janoš Guljaš <janos@resenje.org>
// All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package aes

import (
	"encoding/base64"
	"math/rand"
	"strconv"
	"testing"
)

func TestEncryptDecrypt(t *testing.T) {
	for i, tc := range []struct {
		keyLen    int
		data      string
		opts      []Option
		outputLen int
	}{
		{
			keyLen:    16,
			data:      "testing",
			outputLen: 44,
		},
		{
			keyLen:    57,
			data:      "Z28gZ2V0IHJlc2VuamUub3JnL2NpcGhlcg==",
			outputLen: 90,
		},
		{
			keyLen: 57,
			data:   "Z28gZ2V0IHJlc2VuamUub3JnL2NpcGhlcg==",
			opts: []Option{
				WithInputEncoder(base64.StdEncoding),
			},
			outputLen: 72,
		},
	} {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			key := make([]byte, tc.keyLen)
			n, err := rand.Read(key)
			if err != nil {
				t.Errorf("rand.Read: %s", err)
			}
			if n != tc.keyLen {
				t.Errorf("rand.Read: only %d bytes read out of %d", n, tc.keyLen)
			}

			c := New(key, tc.opts...)

			enc, err := c.EncryptString(tc.data)
			if err != nil {
				t.Fatalf("encrypt: %s", err)
			}
			if len(enc) != tc.outputLen {
				t.Errorf("expected output length %v, got %v", tc.outputLen, len(enc))
			}
			dec, err := c.DecryptString(enc)
			if err != nil {
				t.Fatalf("decrypt: %s", err)
			}
			if tc.data != dec {
				t.Error("original and decrypted data are not equal")
			}
		})
	}
}
