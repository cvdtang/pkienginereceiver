package pkienginereceiver

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.uber.org/zap"
)

type mountMetrics struct {
	ts                 pcommon.Timestamp
	storedCertificates *int64
}

// Initializes mount metrics with the current timestamp.
func newMountMetrics() mountMetrics {
	return mountMetrics{
		ts: pcommon.NewTimestampFromTime(time.Now()),
	}
}

type mountResult struct {
	path               string
	clusterConfig      clusterConfig
	issuerIDs          []string
	certificateSerials []string
	metrics            mountMetrics
}

type mount struct {
	logger      *zap.Logger
	secretStore secretStore
	state       *scrapeShared

	path string
}

// Creates a mount processor for a PKI engine mount path.
func newMount(
	logger *zap.Logger,
	secretStore secretStore,
	state *scrapeShared,

	path string,
) mount {
	return mount{
		logger:      logger.With(zap.String("engine.mount_path", path)),
		secretStore: secretStore,
		state:       state,

		path: path,
	}
}

type clusterConfig struct {
	path    string
	aiaPath string
}

// Get AIA templating values.
func (m *mount) getClusterConfiguration(ctx context.Context) (*clusterConfig, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	secret, err := m.secretStore.readClusterConfiguration(ctx, m.path)
	if err != nil {
		return nil, err
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("empty secret or data")
	}

	path, ok := secret.Data["path"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid path in cluster config")
	}

	aiaPath, ok := secret.Data["aia_path"].(string)
	if !ok {
		return nil, fmt.Errorf("missing or invalid aia_path in cluster config")
	}

	clusterConfig := clusterConfig{
		path:    path,
		aiaPath: aiaPath,
	}

	return &clusterConfig, nil
}

// Lists issuer IDs for the current mount path.
func (m *mount) listIssuers(ctx context.Context) ([]string, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	secret, err := m.secretStore.listIssuers(ctx, m.path)
	if err != nil {
		return nil, fmt.Errorf("failed listing issuers: %w", err)
	}
	if secret == nil {
		return []string{}, nil
	}

	return toStringSlice(secret.Data["keys"]), nil
}

func (m *mount) listCertificates(ctx context.Context) ([]string, error) {
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	secret, err := m.secretStore.listCertificates(ctx, m.path)
	if err != nil {
		return nil, err
	}
	if secret == nil {
		return []string{}, nil
	}

	return toStringSlice(secret.Data["keys"]), nil
}

// Reads mount config, mount metrics and issuer IDs.
func (m *mount) collect(ctx context.Context) (mountResult, error) {
	clusterConfig, err := m.getClusterConfiguration(ctx)
	if err != nil {
		m.logger.Error("failed reading cluster config", zap.Error(err))

		return mountResult{}, fmt.Errorf("failed reading cluster config: %w", err)
	}

	// Bit of a sore thumb as it's used for mount metrics and fan-out.
	var leafs []string
	if m.state.shouldCollectCertificates() {
		leafs, err = m.listCertificates(ctx)
		if err != nil {
			m.logger.Error("failed listing leaf certificates", zap.Error(err))

			return mountResult{}, fmt.Errorf("failed listing leaf certificates: %w", err)
		}
	}

	metrics := m.collectMetrics(int64(len(leafs)))

	issuers, err := m.listIssuers(ctx)
	if err != nil {
		m.logger.Error("failed listing issuers", zap.Error(err))
		issuers = nil
	}

	return mountResult{
		path:               m.path,
		clusterConfig:      *clusterConfig,
		issuerIDs:          issuers,
		certificateSerials: leafs,
		metrics:            metrics,
	}, nil
}

// Gathers mount-level metrics from the secret store.
func (m *mount) collectMetrics(leafs int64) mountMetrics {
	metrics := newMountMetrics()

	if m.state.shouldCollectCertificates() {
		metrics.storedCertificates = &leafs
	}

	return metrics
}
