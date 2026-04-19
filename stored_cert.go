package pkienginereceiver

import (
	"context"
	"errors"
	"fmt"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

type certificateSecret struct {
	certificateData string
	issuerID        string
}

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

	certSecret, err := parseCertificateSecret(secret)
	if err != nil {
		return storedCertResult{}, err
	}

	crt := newCertificate(l.mountPath, metadata.AttributeCertTypeLeaf, certSecret.issuerID, certSecret.certificateData)
	if err := crt.collect(); err != nil {
		return storedCertResult{}, fmt.Errorf("failed processing stored certificate: %w", err)
	}

	return storedCertResult{
		certificate: crt,
	}, nil
}

func parseCertificateSecret(secret *api.Secret) (certificateSecret, error) {
	if secret == nil {
		return certificateSecret{}, errors.New("certificate not found")
	}
	if secret.Data == nil {
		return certificateSecret{}, errors.New("certificate exists but has no data")
	}

	certificateData, ok := secret.Data["certificate"].(string)
	if !ok || certificateData == "" {
		return certificateSecret{}, errors.New("certificate attribute is empty or invalid")
	}

	issuerID, _ := secret.Data["issuer_id"].(string)

	return certificateSecret{
		certificateData: certificateData,
		issuerID:        issuerID,
	}, nil
}
