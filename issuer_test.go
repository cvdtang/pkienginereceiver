package pkienginereceiver

import (
	"encoding/json"
	"testing"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"
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

// Ensures the mount-wide CRL distribution points only apply to issuers without any AIA URLs of their own.
func TestParseIssuerMountCRLURLs(t *testing.T) {
	t.Parallel()

	_, certPEM := getTestCertData(t, "example.org CA")
	mount := mountResult{
		path:          testMountPath,
		clusterConfig: clusterConfig{path: "https://bao.example/v1/pki"},
		crlURLs: crlURLs{
			base:       []string{"{{cluster_path}}/issuer/{{issuer_id}}/crl"},
			delta:      []string{"{{cluster_path}}/issuer/{{issuer_id}}/crl/delta"},
			templating: true,
		},
	}

	tests := []struct {
		name string
		data *issuerData
		want []crlTask
	}{
		{
			name: "no own URLs",
			data: &issuerData{Certificate: string(certPEM)},
			want: []crlTask{
				{
					uri:  "https://bao.example/v1/pki/issuer/issuer-id/crl",
					role: metadata.AttributeCrlRoleSubject,
					kind: metadata.AttributeCrlKindBase,
				},
				{
					uri:  "https://bao.example/v1/pki/issuer/issuer-id/crl/delta",
					role: metadata.AttributeCrlRoleSubject,
					kind: metadata.AttributeCrlKindDelta,
				},
			},
		},
		{
			name: "own issuing certificate URL only",
			data: &issuerData{
				Certificate:         string(certPEM),
				IssuingCertificates: []string{"https://issuer.example/ca"},
			},
			want: nil,
		},
		{
			name: "own OCSP URL only",
			data: &issuerData{
				Certificate: string(certPEM),
				OCSPServers: []string{"https://ocsp.example"},
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			result, err := parseIssuer(zap.NewNop(), tt.data, mount, "issuer-id", crlConfig{Enabled: true})
			require.NoError(t, err)
			assert.ElementsMatch(t, tt.want, result.crlTasks)
		})
	}
}
