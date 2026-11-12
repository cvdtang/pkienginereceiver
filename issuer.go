package pkienginereceiver

import (
	"errors"
	"fmt"

	"go.uber.org/zap"
)

type issuerResult struct {
	mountPath         string
	id                string
	logger            *zap.Logger
	isParent          bool // auto copied over by multi-tier setup
	certificate       certificate
	certificateSerial string
	crlTasks          []crlTask
}

// Parses an issuer read from the secret store and builds its CRL tasks.
func parseIssuer(logger *zap.Logger, data *issuerData, mount mountResult, id string, cfg crlConfig) (issuerResult, error) {
	if data == nil {
		return issuerResult{}, errors.New("issuer not found")
	}

	// Copied parent issuers in intermediate mounts are read-only and have no local key.
	if data.hasNoLocalKey() {
		logger.Debug("skipping non-local issuer")

		return issuerResult{
			mountPath:         mount.path,
			id:                id,
			logger:            logger,
			isParent:          true,
			certificateSerial: parentSerial(logger, data),
		}, nil
	}

	crt, err := newCertificate(data.Certificate)
	if err != nil {
		if data.Certificate == "" {
			return issuerResult{}, errors.New("certificate attribute is empty or invalid")
		}

		return issuerResult{}, fmt.Errorf("failed processing certificate: %w", err)
	}

	logger = logger.WithLazy(
		zap.String("cert.subject.common_name", crt.subjectCN),
		zap.String("cert.issuer.common_name", crt.issuerCN),
	)

	own := crlURLs{
		base:       data.CRLDistributionPoints,
		delta:      data.DeltaCRLDistributionPoints,
		templating: data.EnableAIAURLTemplating,
	}
	tasks, err := crlTasks(cfg, crt, own.resolve(id, mount.clusterConfig))
	if err != nil {
		logger.Error("failed parsing delta CRL extension", zap.Error(err))
	}

	return issuerResult{
		mountPath:         mount.path,
		id:                id,
		logger:            logger,
		certificate:       crt,
		certificateSerial: crt.serial,
		crlTasks:          tasks,
	}, nil
}

// Extracts the certificate serial from a copied parent issuer.
func parentSerial(logger *zap.Logger, data *issuerData) string {
	if data.Certificate == "" {
		return ""
	}

	crt, err := newCertificate(data.Certificate)
	if err != nil {
		logger.Debug("failed parsing copied parent issuer certificate serial", zap.Error(err))

		return ""
	}

	return crt.serial
}
