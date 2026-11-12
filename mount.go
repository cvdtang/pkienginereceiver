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
	crlURLs            crlURLs
	issuerIDs          []string
	certificateSerials []string

	ts pcommon.Timestamp
	// Number of stored certificates, nil when certificates are not listed.
	storedCertificates *int64
}

// Optional reads of a mount.
type mountOptions struct {
	// Lists the stored certificates, for the stored certificates metric and leaf collection.
	listCertificates bool
	// Reads the mount-wide URL configuration, for CRL discovery.
	readURLs bool
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
func readMount(ctx context.Context, store secretStore, path string, opts mountOptions) (mountResult, error) {
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

	if opts.readURLs {
		urlData, err := store.readURLConfiguration(ctx, path)
		if err != nil {
			return mountResult{}, fmt.Errorf("failed reading url config: %w", err)
		}
		if urlData != nil {
			result.crlURLs = crlURLs{
				base:       urlData.CRLDistributionPoints,
				delta:      urlData.DeltaCRLDistributionPoints,
				templating: urlData.EnableTemplating,
			}
		}
	}

	if opts.listCertificates {
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
