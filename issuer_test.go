package pkienginereceiver

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

// Ensures unparsable issuers are reported as errors and copied parent issuers are recognized by their missing key.
func TestParseIssuer(t *testing.T) {
	t.Parallel()

	_, certPEM := getTestCertData(t, "example.org CA")

	tests := []struct {
		name       string
		data       *issuerData
		wantErr    string
		wantParent bool
	}{
		{
			name:    "not found",
			data:    nil,
			wantErr: "issuer not found",
		},
		{
			name:    "invalid certificate",
			data:    &issuerData{Certificate: "junk"},
			wantErr: "failed processing certificate",
		},
		{
			name: "copied parent with empty key id",
			data: &issuerData{
				Certificate: string(certPEM),
				KeyID:       json.RawMessage(`""`),
			},
			wantParent: true,
		},
		{
			name: "local issuer without key id field",
			data: &issuerData{Certificate: string(certPEM)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := parseIssuer(zap.NewNop(), tt.data, mountResult{path: testMountPath}, testIssuerID, createDefaultConfig().(*config).Crl)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantParent, result.isParent)
			assert.Equal(t, "30:39", result.certificateSerial)
		})
	}
}
