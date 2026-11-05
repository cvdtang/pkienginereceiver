package pkienginereceiver

import (
	"context"
	"errors"
	"fmt"
)

// Reads and parses a stored certificate.
func readStoredCertificate(ctx context.Context, store secretStore, mountPath, serial string) (certificate, error) {
	data, err := store.readCertificate(ctx, mountPath, serial)
	if err != nil {
		return certificate{}, err
	}
	if data == nil {
		return certificate{}, errors.New("certificate not found")
	}
	if data.Certificate == "" {
		return certificate{}, errors.New("certificate attribute is empty or invalid")
	}

	crt, err := newCertificate(data.Certificate)
	if err != nil {
		return certificate{}, fmt.Errorf("failed processing stored certificate: %w", err)
	}

	return crt, nil
}
