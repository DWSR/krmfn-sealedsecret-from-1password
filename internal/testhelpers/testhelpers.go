// testhelpers package provides helper functions for testing.
package testhelpers

import (
	"context"
	"errors"
)

type (
	// MockResolver is a mock implementation of the Resolver interface from the onepassword package.
	MockResolver struct {
		lookup map[string]string
	}

	// StaticReader is a simple io.Reader that reads from a predefined 64-byte slice.
	StaticReader struct {
		data []byte
		pos  int
	}
)

// ErrMockResolverNoLookup is returned when the secret reference is not found in the lookup map.
var ErrMockResolverNoLookup = errors.New("no lookup for secret in mock resolver")

// Resolve returns the value from the lookup map for the given secret reference.
func (r MockResolver) Resolve(_ context.Context, secretReference string) (string, error) {
	if val, ok := r.lookup[secretReference]; ok {
		return val, nil
	}

	return "", ErrMockResolverNoLookup
}

// NewMockResolver creates a new MockResolver with the given lookup map.
func NewMockResolver(lookup map[string]string) MockResolver {
	return MockResolver{lookup: lookup}
}

// NewStaticReader creates a new StaticReader with a predefined 64-byte slice.
func NewStaticReader() *StaticReader {
	data := []byte("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@")

	return &StaticReader{
		data: data,
		pos:  0,
	}
}

func (sr *StaticReader) Read(ptr []byte) (int, error) {
	n := len(ptr)
	readBytes := 0

	for readBytes < n {
		remaining := len(sr.data) - sr.pos
		toRead := n - readBytes

		if toRead > remaining {
			toRead = remaining
		}

		copy(ptr[readBytes:], sr.data[sr.pos:sr.pos+toRead])
		readBytes += toRead
		sr.pos += toRead

		// Reset position if we reach the end of the data
		if sr.pos == len(sr.data) {
			sr.pos = 0
		}
	}

	return readBytes, nil
}
