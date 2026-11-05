package pkienginereceiver

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func createTestCrlTemplate(tb testing.TB, tmpl *x509.RevocationList) []byte {
	tb.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(tb, err)
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Summary CA", Organization: []string{"Org"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &key.PublicKey, key)
	require.NoError(tb, err)
	ca, err := x509.ParseCertificate(caDER)
	require.NoError(tb, err)

	der, err := x509.CreateRevocationList(rand.Reader, tmpl, ca, key)
	require.NoError(tb, err)

	return der
}

// Asserts summarizeCRL matches x509.ParseRevocationList for the given input.
func assertCRLSummaryMatchesStdlib(t *testing.T, data []byte) {
	t.Helper()

	got, gotErr := summarizeCRL(data)
	want, wantErr := parseCRL(data)
	if wantErr != nil {
		require.Error(t, gotErr, "stdlib failed with %v", wantErr)

		return
	}
	require.NoError(t, gotErr)
	assert.Equal(t, want.Issuer.CommonName, got.issuerCommonName)
	assert.True(t, want.ThisUpdate.Equal(got.thisUpdate))
	assert.True(t, want.NextUpdate.Equal(got.nextUpdate))
	assert.Equal(t, int64(len(want.RevokedCertificateEntries)), got.revokedCertificates)
	assert.Equal(t, countCRLRevokedCertificatesByReason(want.RevokedCertificateEntries), got.revokedCertificatesByReason)
}

func TestSummarizeCRLMatchesStdlib(t *testing.T) {
	t.Parallel()

	now := time.Now().Truncate(time.Second)
	invalidityDateExt := pkix.Extension{
		Id:    asn1.ObjectIdentifier{2, 5, 29, 24},
		Value: []byte{0x18, 0x0f, '2', '0', '2', '4', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z'},
	}

	entries := make([]x509.RevocationListEntry, 0, 64)
	for i := range 64 {
		entries = append(entries, x509.RevocationListEntry{
			SerialNumber:   new(big.Int).Lsh(big.NewInt(int64(i+1)), uint(i)),
			RevocationTime: now.Add(-time.Duration(i) * time.Hour),
			ReasonCode:     i % crlRevocationReasonSlots,
		})
	}

	tests := []struct {
		name string
		tmpl *x509.RevocationList
	}{
		{
			name: "no entries",
			tmpl: &x509.RevocationList{Number: big.NewInt(1), ThisUpdate: now, NextUpdate: now.Add(time.Hour)},
		},
		{
			name: "all reason codes",
			tmpl: &x509.RevocationList{Number: big.NewInt(2), ThisUpdate: now, NextUpdate: now.Add(time.Hour), RevokedCertificateEntries: entries},
		},
		{
			name: "generalized time beyond 2049",
			tmpl: &x509.RevocationList{
				Number:     big.NewInt(3),
				ThisUpdate: time.Date(2051, 1, 1, 0, 0, 0, 0, time.UTC),
				NextUpdate: time.Date(2052, 1, 1, 0, 0, 0, 0, time.UTC),
				RevokedCertificateEntries: []x509.RevocationListEntry{
					{SerialNumber: big.NewInt(7), RevocationTime: time.Date(2050, 6, 1, 0, 0, 0, 0, time.UTC)},
				},
			},
		},
		{
			name: "extra entry extensions",
			tmpl: &x509.RevocationList{
				Number: big.NewInt(4), ThisUpdate: now, NextUpdate: now.Add(time.Hour),
				RevokedCertificateEntries: []x509.RevocationListEntry{
					{SerialNumber: big.NewInt(8), RevocationTime: now, ReasonCode: crlReasonSuperseded, ExtraExtensions: []pkix.Extension{invalidityDateExt}},
					{SerialNumber: big.NewInt(9), RevocationTime: now, ExtraExtensions: []pkix.Extension{invalidityDateExt}},
					{SerialNumber: big.NewInt(10), RevocationTime: now, ReasonCode: 42},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			der := createTestCrlTemplate(t, tc.tmpl)
			assertCRLSummaryMatchesStdlib(t, der)
			assertCRLSummaryMatchesStdlib(t, pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}))

			// Corrupted and truncated inputs must fail like the standard library.
			for _, cut := range []int{1, len(der) / 3, len(der) / 2, len(der) - 1} {
				assertCRLSummaryMatchesStdlib(t, der[:cut])
			}
			for _, pos := range []int{2, 5, len(der) / 2, len(der) - 3} {
				corrupted := append([]byte(nil), der...)
				corrupted[pos] ^= 0xff
				_, gotErr := summarizeCRL(corrupted)
				_, wantErr := parseCRL(corrupted)
				if wantErr != nil {
					require.Error(t, gotErr, "pos %d: stdlib failed with %v", pos, wantErr)
				}
			}
		})
	}
}

func TestSummarizeCRLInvalid(t *testing.T) {
	t.Parallel()

	for _, input := range [][]byte{nil, []byte("junk"), {0x30, 0x00}, {0x30, 0x03, 0x30, 0x01, 0x00}} {
		_, err := summarizeCRL(input)
		require.Error(t, err)
	}
}

func FuzzSummarizeCRL(f *testing.F) {
	f.Add(createTestCrlTemplate(f, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: []x509.RevocationListEntry{
			{SerialNumber: big.NewInt(2), RevocationTime: time.Now(), ReasonCode: crlReasonKeyCompromise},
			{SerialNumber: big.NewInt(3), RevocationTime: time.Now()},
		},
	}))

	f.Fuzz(func(t *testing.T, data []byte) {
		got, gotErr := summarizeCRL(data)
		want, wantErr := parseCRL(data)
		if wantErr != nil || gotErr != nil {
			// The summary skips revocation date contents, so it may accept
			// CRLs the standard library rejects, but never the reverse.
			if wantErr == nil {
				t.Fatalf("summary failed on valid CRL: %v", gotErr)
			}

			return
		}
		if int64(len(want.RevokedCertificateEntries)) != got.revokedCertificates ||
			countCRLRevokedCertificatesByReason(want.RevokedCertificateEntries) != got.revokedCertificatesByReason ||
			want.Issuer.CommonName != got.issuerCommonName ||
			!want.ThisUpdate.Equal(got.thisUpdate) || !want.NextUpdate.Equal(got.nextUpdate) {
			t.Fatalf("summary mismatch")
		}
	})
}

func BenchmarkCRLParse(b *testing.B) {
	entries := make([]x509.RevocationListEntry, 100_000)
	for i := range entries {
		entries[i] = x509.RevocationListEntry{
			SerialNumber:   new(big.Int).Lsh(big.NewInt(int64(i+1)), 100),
			RevocationTime: time.Now(),
			ReasonCode:     i % 6,
		}
	}
	der := createTestCrlTemplate(b, &x509.RevocationList{
		Number: big.NewInt(1), ThisUpdate: time.Now(), NextUpdate: time.Now().Add(time.Hour),
		RevokedCertificateEntries: entries,
	})
	b.SetBytes(int64(len(der)))

	b.Run("stdlib", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := createCRLMetricsStdlib(der); err != nil {
				b.Fatal(err)
			}
		}
	})
	b.Run("summary", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if _, err := summarizeCRL(der); err != nil {
				b.Fatal(err)
			}
		}
	})
}

func createCRLMetricsStdlib(der []byte) ([crlRevocationReasonSlots]int64, error) {
	rl, err := parseCRL(der)
	if err != nil {
		return [crlRevocationReasonSlots]int64{}, err
	}

	return countCRLRevokedCertificatesByReason(rl.RevokedCertificateEntries), nil
}

// Counts CRL `revokedCertificates` entries per RFC 5280 Section 5.3.1 reason.
func countCRLRevokedCertificatesByReason(entries []x509.RevocationListEntry) [crlRevocationReasonSlots]int64 {
	var byReason [crlRevocationReasonSlots]int64

	for i := range entries {
		byReason[crlReasonSlot(entries[i].ReasonCode)]++
	}

	return byReason
}

// Decodes and parses CRL bytes from PEM or DER format with the standard library, as reference for summarizeCRL.
func parseCRL(data []byte) (*x509.RevocationList, error) {
	block, _ := pem.Decode(data)
	if block != nil {
		data = block.Bytes
	}

	return x509.ParseRevocationList(data)
}
