package pkienginereceiver

import (
	"context"
	"fmt"

	"go.uber.org/zap"
)

// Returns PKI mount paths that match the configured regex.
func getFilteredMounts(ctx context.Context, logger *zap.Logger, secretStore secretStore, cfg config) ([]string, error) {
	pkiMountPaths, err := secretStore.listMountPathsTypePki(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to list pki mounts: %w", err)
	}

	if len(pkiMountPaths) == 0 {
		logger.Warn("no engine mounts found of type pki")

		return nil, nil
	}

	var filteredMountPaths []string
	for _, mountPath := range pkiMountPaths {
		if cfg.compiledRegex.MatchString(mountPath) {
			filteredMountPaths = append(filteredMountPaths, mountPath)
		}
	}

	if len(filteredMountPaths) == 0 {
		logger.Warn("no engine mounts matched the provided regex",
			zap.Int("total_pki_mounts", len(pkiMountPaths)),
			zap.String("regex", cfg.MatchRegex),
		)

		return nil, nil
	}

	logger.Debug("discovered mounts for scraping",
		zap.Int("matched_count", len(filteredMountPaths)),
	)

	return filteredMountPaths, nil
}
