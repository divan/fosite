// Copyright © 2025 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package hmac

import (
	"crypto/rand"
	"io"

	"github.com/pkg/errors"
)

// RandomBytes returns n random bytes by reading from crypto/rand.Reader
func RandomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)
	if _, err := io.ReadFull(rand.Reader, bytes); err != nil {
		return nil, errors.WithStack(err)
	}
	return bytes, nil
}
