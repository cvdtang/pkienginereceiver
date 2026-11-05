package pkienginereceiver

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.uber.org/zap"
)

type mountResult struct {
	path               string
	clusterConfig      clusterConfig
	issuerIDs          []string
	certificateSerials []string

	ts pcommon.Timestamp
	// Number of stored certificates, nil when certificates are not listed.
	storedCertificates *int64
}

type mount struct {
	logger      *zap.Logger
	secretStore secretStore

	path string
	// Whether stored certificates are listed, for the stored certificates metric and leaf collection.
	listCertificates bool
}

// Creates a mount processor for a PKI engine mount path.
func newMount(
	logger *zap.Logger,
	secretStore secretStore,

	path string,
	listCertificates bool,
) mount {
	return mount{
		logger:      logger.WithLazy(zap.String("engine.mount_path", path)),
		secretStore: secretStore,

		path:             path,
		listCertificates: listCertificates,
	}
}

type clusterConfig struct {
	path    string
	aiaPath string
}

// Extracts AIA templating values from the cluster configuration.
func parseClusterConfig(data *clusterConfigData) (clusterConfig, error) {
	if data == nil {
		return clusterConfig{}, fmt.Errorf("empty cluster config")
	}
	if data.Path == nil {
		return clusterConfig{}, fmt.Errorf("missing or invalid path in cluster config")
	}
	if data.AIAPath == nil {
		return clusterConfig{}, fmt.Errorf("missing or invalid aia_path in cluster config")
	}

	return clusterConfig{
		path:    *data.Path,
		aiaPath: *data.AIAPath,
	}, nil
}

// Reads mount config, mount metrics and issuer IDs.
func (m *mount) collect(ctx context.Context) (mountResult, error) {
	data, err := m.secretStore.readClusterConfiguration(ctx, m.path)
	var clusterConfig clusterConfig
	if err == nil {
		clusterConfig, err = parseClusterConfig(data)
	}
	if err != nil {
		m.logger.Error("failed reading cluster config", zap.Error(err))

		return mountResult{}, fmt.Errorf("failed reading cluster config: %w", err)
	}

	result := mountResult{
		path:          m.path,
		clusterConfig: clusterConfig,
	}

	if m.listCertificates {
		result.certificateSerials, err = m.secretStore.listCertificates(ctx, m.path)
		if err != nil {
			m.logger.Error("failed listing leaf certificates", zap.Error(err))

			return mountResult{}, fmt.Errorf("failed listing leaf certificates: %w", err)
		}
		storedCertificates := int64(len(result.certificateSerials))
		result.storedCertificates = &storedCertificates
	}
	result.ts = pcommon.NewTimestampFromTime(time.Now())

	result.issuerIDs, err = m.secretStore.listIssuers(ctx, m.path)
	if err != nil {
		m.logger.Error("failed listing issuers", zap.Error(err))

		return mountResult{}, fmt.Errorf("failed listing issuers: %w", err)
	}

	return result, nil
}
