// Copyright 2014 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// +build go1.4

package sha3

import (
	"crypto"
)

func init() {
	kyber.RegisterHash(kyber.SHA3_224, New224)
	kyber.RegisterHash(kyber.SHA3_256, New256)
	kyber.RegisterHash(kyber.SHA3_384, New384)
	kyber.RegisterHash(kyber.SHA3_512, New512)
}
