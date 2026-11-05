package pkienginereceiver

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadStoredCertificate(t *testing.T) {
	t.Parallel()

	_, certPEM := getTestCertData(t, "leaf.example.org")

	tests := []struct {
		name       string
		data       *certificateData
		readErr    error
		wantErr    string
		wantSerial string
	}{
		{
			name:       "success",
			data:       &certificateData{Certificate: string(certPEM)},
			wantSerial: "30:39",
		},
		{
			name:    "read error",
			readErr: errors.New("boom"),
			wantErr: "boom",
		},
		{
			name:    "not found",
			wantErr: "certificate not found",
		},
		{
			name:    "empty certificate attribute",
			data:    &certificateData{},
			wantErr: "certificate attribute is empty or invalid",
		},
		{
			name:    "invalid certificate",
			data:    &certificateData{Certificate: "junk"},
			wantErr: "failed processing stored certificate",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			ctx := t.Context()

			mockSecretStore := newMocksecretStore(t)
			mockSecretStore.On("readCertificate", ctx, "pki/", "01:23").Return(tt.data, tt.readErr)

			crt, err := readStoredCertificate(ctx, mockSecretStore, "pki/", "01:23")
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantSerial, crt.serial)
		})
	}
}
