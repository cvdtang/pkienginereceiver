package pkienginereceiver

import (
	"errors"
	"regexp"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestGetFilteredMounts(t *testing.T) {
	t.Parallel()

	logger := zap.NewNop()

	tests := []struct {
		name           string
		regex          string
		mockReturn     []string
		mockErr        error
		expectedResult []string
		expectErr      bool
	}{
		{
			name:       "Error from api",
			regex:      ".*",
			mockReturn: nil,
			mockErr:    errors.New("api error"),
			expectErr:  true,
		},
		{
			name:           "No PKI mounts found",
			regex:          ".*",
			mockReturn:     []string{},
			mockErr:        nil,
			expectedResult: nil,
			expectErr:      false,
		},
		{
			name:           "Mounts found but none match regex",
			regex:          "^pki/v2/.*",
			mockReturn:     []string{"pki/v1/ica/v1"},
			mockErr:        nil,
			expectedResult: nil,
			expectErr:      false,
		},
		{
			name:           "Successful regex match",
			regex:          "^pki/v1/.*",
			mockReturn:     []string{"pki/v1/ica/v1", "pki/v1/ica/v2"},
			mockErr:        nil,
			expectedResult: []string{"pki/v1/ica/v1", "pki/v1/ica/v2"},
			expectErr:      false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			// Setup
			mocksecretStore := newMocksecretStore(t)
			mocksecretStore.On("listMountPathsTypePki", ctx).Return(tt.mockReturn, tt.mockErr).Once()

			cfg := config{
				MatchRegex:    tt.regex,
				compiledRegex: regexp.MustCompile(tt.regex),
			}

			// Execute
			result, err := getFilteredMounts(ctx, logger, mocksecretStore, cfg)

			// Assert
			if tt.expectErr {
				require.Error(t, err)
				assert.Nil(t, result)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.expectedResult, result)
			}
		})
	}
}
