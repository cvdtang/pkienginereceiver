package pkienginereceiver

import (
	"context"
	"fmt"
	"time"

	"go.opentelemetry.io/collector/pdata/pcommon"
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

// Reads the cluster configuration and the issuer IDs of a mount.
func readMount(ctx context.Context, store secretStore, path string, listCertificates bool) (mountResult, error) {
	clusterData, err := store.readClusterConfiguration(ctx, path)
	var cluster clusterConfig
	if err == nil {
		cluster, err = parseClusterConfig(clusterData)
	}
	if err != nil {
		return mountResult{}, fmt.Errorf("failed reading cluster config: %w", err)
	}

	result := mountResult{
		path:          path,
		clusterConfig: cluster,
	}

	if listCertificates {
		result.certificateSerials, err = store.listCertificates(ctx, path)
		if err != nil {
			return mountResult{}, fmt.Errorf("failed listing leaf certificates: %w", err)
		}
		result.storedCertificates = new(int64(len(result.certificateSerials)))
	}
	result.ts = pcommon.NewTimestampFromTime(time.Now())

	result.issuerIDs, err = store.listIssuers(ctx, path)
	if err != nil {
		return mountResult{}, fmt.Errorf("failed listing issuers: %w", err)
	}

	return result, nil
}
