package pkienginereceiver

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

type storedCert struct {
	logger      *zap.Logger
	secretStore secretStore

	mountPath string
	serial    string
}

type storedCertResult struct {
	certificate certificate
}

func newStoredCert(
	logger *zap.Logger,
	secretStore secretStore,

	mountPath string,
	serial string,
) storedCert {
	return storedCert{
		logger:      logger.With(zap.String("cert.serial", serial)),
		secretStore: secretStore,
		mountPath:   mountPath,
		serial:      serial,
	}
}

func (l *storedCert) collect(ctx context.Context) (storedCertResult, error) {
	if ctx.Err() != nil {
		return storedCertResult{}, ctx.Err()
	}

	secret, err := l.secretStore.readCertificate(ctx, l.mountPath, l.serial)
	if err != nil {
		return storedCertResult{}, err
	}

	certData, err := parseCertificateData(secret)
	if err != nil {
		return storedCertResult{}, err
	}

	crt, err := newCertificate(certData)
	if err != nil {
		return storedCertResult{}, fmt.Errorf("failed processing stored certificate: %w", err)
	}

	return storedCertResult{
		certificate: crt,
	}, nil
}

// Extracts the raw certificate data from a certificate secret.
func parseCertificateData(secret *api.Secret) (string, error) {
	if secret == nil {
		return "", errors.New("certificate not found")
	}
	if secret.Data == nil {
		return "", errors.New("certificate exists but has no data")
	}

	certificateData, ok := secret.Data["certificate"].(string)
	if !ok || certificateData == "" {
		return "", errors.New("certificate attribute is empty or invalid")
	}

	return certificateData, nil
}
