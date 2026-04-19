package pkienginereceiver

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"

	"github.com/hashicorp/vault/api"
	"go.uber.org/zap"
)

type issuer struct {
	logger      *zap.Logger
	secretStore secretStore
	state       *scrapeShared

	mountPath     string
	id            string
	clusterConfig clusterConfig
}

// Creates an issuer processor for a mount and issuer ID.
func newIssuer(
	logger *zap.Logger,
	secretStore secretStore,
	state *scrapeShared,

	mountPath string,
	id string,
	clusterConfig clusterConfig,
) issuer {
	return issuer{
		logger:        logger.With(zap.String("issuer.id", id)),
		secretStore:   secretStore,
		state:         state,
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
	skipped           bool
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

func (ie *issuer) renderAiaUrlTemplate(url string) string {
	return renderAiaUrlTemplate(url, ie.id, ie.clusterConfig)
}

// Reads issuer data, processes the certificate and prepares CRL tasks.
func (ie *issuer) collect(ctx context.Context) (issuerResult, error) {
	var err error
	var issuer *api.Secret

	if ctx.Err() != nil {
		return issuerResult{}, ctx.Err()
	}
	issuer, err = ie.secretStore.readIssuer(ctx, ie.mountPath, ie.id)

	if err != nil {
		ie.logger.Error("failed reading issuer", zap.Error(err))

		return issuerResult{}, err
	}

	if issuer == nil {
		return issuerResult{}, errors.New("issuer not found")
	}

	if issuer.Data == nil {
		return issuerResult{}, errors.New("issuer exists but has no data")
	}

	if skip, isParent := ie.shouldSkip(issuer); skip {
		return ie.newSkippedIssuerResult(issuer, isParent), nil
	}

	certSecret, err := parseCertificateSecret(issuer)
	if err != nil {
		return issuerResult{}, err
	}

	crt := newCertificate(ie.mountPath, metadata.AttributeCertTypeIssuer, ie.id, certSecret.certificateData)
	if err := crt.collect(); err != nil {
		return issuerResult{}, fmt.Errorf("failed processing certificate: %w", err)
	}

	issuerLogger := ie.logger.With(
		zap.String("cert.subject.common_name", crt.crt.Subject.CommonName),
		zap.String("cert.issuer.common_name", crt.crt.Issuer.CommonName),
	)

	crlTasks := ie.buildCRLTasks(issuer, crt, issuerLogger)

	return issuerResult{
		mountPath:         ie.mountPath,
		id:                ie.id,
		logger:            issuerLogger,
		certificate:       crt,
		certificateSerial: crt.serial(),
		crlTasks:          crlTasks,
	}, nil
}

func (ie *issuer) shouldSkip(issuer *api.Secret) (bool, bool) {
	// Copied parent issuers in intermediate mounts are read-only and have no local key.
	keyID, exists := issuer.Data["key_id"]
	if !exists {
		return false, false
	}
	if keyID == nil {
		ie.logger.Debug("skipping non-local issuer (nil key_id)")

		return true, true
	}
	keyIDStr, ok := keyID.(string)
	if ok && keyIDStr == "" {
		ie.logger.Debug("skipping non-local issuer (empty key_id)")

		return true, true
	}

	return false, false
}

// Extracts the certificate serial from a copied parent issuer secret.
func (ie *issuer) parentSerialFromIssuerSecret(issuer *api.Secret) string {
	certSecret, err := parseCertificateSecret(issuer)
	if err != nil {
		return ""
	}

	crt := newCertificate(ie.mountPath, metadata.AttributeCertTypeIssuer, ie.id, certSecret.certificateData)
	if err := crt.collect(); err != nil {
		ie.logger.Debug("failed parsing copied parent issuer certificate serial", zap.Error(err))

		return ""
	}

	return crt.serial()
}

func (ie *issuer) newSkippedIssuerResult(issuer *api.Secret, isParent bool) issuerResult {
	parentSerial := ""
	if isParent {
		parentSerial = ie.parentSerialFromIssuerSecret(issuer)
	}

	return issuerResult{
		mountPath:         ie.mountPath,
		id:                ie.id,
		logger:            ie.logger,
		skipped:           true,
		isParent:          isParent,
		certificateSerial: parentSerial,
	}
}

// Creates CRL tasks from issuer and certificate distribution points.
func (ie *issuer) buildCRLTasks(issuer *api.Secret, cert certificate, logger *zap.Logger) []crlTask {
	if !ie.state.cfg.Crl.Enabled {
		return nil
	}

	tasks := make([]crlTask, 0)
	appendTasks := func(urls []string, role metadata.AttributeCrlRole, kind metadata.AttributeCrlKind) {
		tasks = append(tasks, ie.buildCRLTasksForURIs(issuer, urls, role, kind)...)
	}

	appendTasks(ie.listBaseCrlDistributionPoints(issuer), metadata.AttributeCrlRoleSubject, metadata.AttributeCrlKindBase)
	appendTasks(ie.listDeltaCrlDistributionPoints(issuer), metadata.AttributeCrlRoleSubject, metadata.AttributeCrlKindDelta)

	if !ie.state.cfg.Crl.ScrapeParent {
		return tasks
	}

	appendTasks(cert.listBaseCrlDistributionPoints(), metadata.AttributeCrlRoleIssuer, metadata.AttributeCrlKindBase)

	deltaIssuerURIs, err := cert.listDeltaCrlDistributionPoints()
	if err != nil {
		logger.Error("failed parsing delta CRL extension")

		return tasks
	}
	appendTasks(deltaIssuerURIs, metadata.AttributeCrlRoleIssuer, metadata.AttributeCrlKindDelta)

	return tasks
}

// Converts raw URIs to labelled CRL task entries.
func (ie *issuer) buildCRLTasksForURIs(issuer *api.Secret, urls []string, role metadata.AttributeCrlRole, kind metadata.AttributeCrlKind) []crlTask {
	if len(urls) == 0 {
		return nil
	}

	tasks := make([]crlTask, 0, len(urls))
	for _, rawURI := range urls {
		realURI := rawURI
		if issuer != nil && issuer.Data != nil {
			if enable, ok := issuer.Data["enable_aia_url_templating"].(bool); ok && enable {
				realURI = ie.renderAiaUrlTemplate(rawURI)
			}
		}
		tasks = append(tasks, crlTask{
			uri:  realURI,
			role: role,
			kind: kind,
		})
	}

	return tasks
}

func (ie *issuer) listBaseCrlDistributionPoints(issuer *api.Secret) []string {
	return toStringSlice(issuer.Data["crl_distribution_points"])
}

func (ie *issuer) listDeltaCrlDistributionPoints(issuer *api.Secret) []string {
	return toStringSlice(issuer.Data["delta_crl_distribution_points"])
}
