package pkienginereceiver

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"

	"github.com/hashicorp/vault/sdk/helper/certutil"
	"go.uber.org/zap"
)

type issuer struct {
	logger      *zap.Logger
	secretStore secretStore
	crlConfig   crlConfig

	mountPath     string
	id            string
	clusterConfig clusterConfig
}

// Creates an issuer processor for a mount and issuer ID.
func newIssuer(
	logger *zap.Logger,
	secretStore secretStore,
	crlConfig crlConfig,

	mountPath string,
	id string,
	clusterConfig clusterConfig,
) issuer {
	return issuer{
		logger:        logger.WithLazy(zap.String("issuer.id", id)),
		secretStore:   secretStore,
		crlConfig:     crlConfig,
		mountPath:     mountPath,
		id:            id,
		clusterConfig: clusterConfig,
	}
}

type crlTask struct {
	uri  string
	role metadata.AttributeCrlRole
	kind metadata.AttributeCrlKind
}

type issuerResult struct {
	mountPath         string
	id                string
	logger            *zap.Logger
	isParent          bool // auto copied over by multi-tier setup
	certificate       certificate
	certificateSerial string
	crlTasks          []crlTask
}

// Resolves supported AIA placeholders in an URI template.
func renderAiaUrlTemplate(url string, issuerID string, clusterConfig clusterConfig) string {
	if !strings.Contains(url, "{{") {
		return url
	}

	url = strings.ReplaceAll(url, "{{issuer_id}}", issuerID)
	url = strings.ReplaceAll(url, "{{cluster_path}}", clusterConfig.path)
	url = strings.ReplaceAll(url, "{{cluster_aia_path}}", clusterConfig.aiaPath)

	return url
}

// Reads issuer data, processes the certificate and prepares CRL tasks.
func (ie *issuer) collect(ctx context.Context) (issuerResult, error) {
	data, err := ie.secretStore.readIssuer(ctx, ie.mountPath, ie.id)
	if err != nil {
		ie.logger.Error("failed reading issuer", zap.Error(err))

		return issuerResult{}, err
	}

	if data == nil {
		return issuerResult{}, errors.New("issuer not found")
	}

	// Copied parent issuers in intermediate mounts are read-only and have no local key.
	if data.hasNoLocalKey() {
		ie.logger.Debug("skipping non-local issuer")

		return issuerResult{
			mountPath:         ie.mountPath,
			id:                ie.id,
			logger:            ie.logger,
			isParent:          true,
			certificateSerial: ie.parentSerial(data),
		}, nil
	}

	crt, err := newCertificate(data.Certificate)
	if err != nil {
		if data.Certificate == "" {
			return issuerResult{}, errors.New("certificate attribute is empty or invalid")
		}

		return issuerResult{}, fmt.Errorf("failed processing certificate: %w", err)
	}

	issuerLogger := ie.logger.WithLazy(
		zap.String("cert.subject.common_name", crt.subjectCN),
		zap.String("cert.issuer.common_name", crt.issuerCN),
	)

	return issuerResult{
		mountPath:         ie.mountPath,
		id:                ie.id,
		logger:            issuerLogger,
		certificate:       crt,
		certificateSerial: crt.serial,
		crlTasks:          ie.buildCRLTasks(data, crt, issuerLogger),
	}, nil
}

// Extracts the certificate serial from a copied parent issuer.
func (ie *issuer) parentSerial(data *issuerData) string {
	if data.Certificate == "" {
		return ""
	}

	crt, err := newCertificate(data.Certificate)
	if err != nil {
		ie.logger.Debug("failed parsing copied parent issuer certificate serial", zap.Error(err))

		return ""
	}

	return crt.serial
}

// Creates CRL tasks from issuer and certificate distribution points.
func (ie *issuer) buildCRLTasks(data *issuerData, cert certificate, logger *zap.Logger) []crlTask {
	if !ie.crlConfig.Enabled {
		return nil
	}

	tasks := make([]crlTask, 0)
	appendTasks := func(urls []string, role metadata.AttributeCrlRole, kind metadata.AttributeCrlKind) {
		tasks = append(tasks, ie.buildCRLTasksForURIs(data, urls, role, kind)...)
	}

	appendTasks(data.CRLDistributionPoints, metadata.AttributeCrlRoleSubject, metadata.AttributeCrlKindBase)
	appendTasks(data.DeltaCRLDistributionPoints, metadata.AttributeCrlRoleSubject, metadata.AttributeCrlKindDelta)

	if !ie.crlConfig.ScrapeParent {
		return tasks
	}

	appendTasks(cert.cert.CRLDistributionPoints, metadata.AttributeCrlRoleIssuer, metadata.AttributeCrlKindBase)

	deltaIssuerURIs, err := certutil.ParseDeltaCRLExtension(cert.cert)
	if err != nil {
		logger.Error("failed parsing delta CRL extension")

		return tasks
	}
	appendTasks(deltaIssuerURIs, metadata.AttributeCrlRoleIssuer, metadata.AttributeCrlKindDelta)

	return tasks
}

// Converts raw URIs to labelled CRL task entries.
func (ie *issuer) buildCRLTasksForURIs(data *issuerData, urls []string, role metadata.AttributeCrlRole, kind metadata.AttributeCrlKind) []crlTask {
	if len(urls) == 0 {
		return nil
	}

	tasks := make([]crlTask, 0, len(urls))
	for _, rawURI := range urls {
		realURI := rawURI
		if data != nil && data.EnableAIAURLTemplating {
			realURI = renderAiaUrlTemplate(rawURI, ie.id, ie.clusterConfig)
		}
		tasks = append(tasks, crlTask{
			uri:  realURI,
			role: role,
			kind: kind,
		})
	}

	return tasks
}
