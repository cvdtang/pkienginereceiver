package pkienginereceiver

import (
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/cvdtang/pkienginereceiver/internal/metadata"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.uber.org/zap/zaptest"
)

const (
	ldapRootDN = "cn=admin,dc=example,dc=org"
	ldapRootPW = "ldap-test-password"
)

type ldapContainer struct {
	container testcontainers.Container
	host      string
	port      string
	rootDN    string
	rootPW    string
}

// Starts the self-built OpenLDAP image from test/ldap.
func startLDAPContainer(t *testing.T, ctx context.Context) (*ldapContainer, error) {
	t.Helper()

	req := testcontainers.ContainerRequest{
		FromDockerfile: testcontainers.FromDockerfile{
			Context:    "test/ldap",
			Dockerfile: "Dockerfile",
			KeepImage:  true,
		},
		ExposedPorts: []string{"389/tcp"},
		// Require an anonymous bind to succeed before seeding.
		WaitingFor: wait.ForAll(
			wait.ForListeningPort("389/tcp"),
			wait.ForExec([]string{"ldapwhoami", "-x", "-H", "ldap://localhost:389"}),
		),
	}
	container, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, err
	}

	host, err := container.Host(ctx)
	if err != nil {
		return nil, err
	}
	natPort, err := container.MappedPort(ctx, "389/tcp")
	if err != nil {
		return nil, err
	}

	return &ldapContainer{
		container: container,
		host:      host,
		port:      natPort.Port(),
		rootDN:    ldapRootDN,
		rootPW:    ldapRootPW,
	}, nil
}

type ldapSeedEntry struct {
	dn     string
	cn     string
	crlDER []byte
}

// Builds DER bytes that are structurally valid for slapd's CertificateList
// syntax check yet fail Go's x509.ParseRevocationList: the outer signature
// algorithm identifier's OID is mutated so it no longer matches the one inside
// the tbsCertList.
func makeCorruptCrlDER(t *testing.T) []byte {
	t.Helper()

	der, _ := createTestCrlData(t)

	sha256AI := []byte{0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b, 0x05, 0x00}
	first := bytes.Index(der, sha256AI)
	require.GreaterOrEqual(t, first, 0, "tbs signatureAlgorithm identifier not found")
	second := bytes.Index(der[first+1:], sha256AI)
	require.GreaterOrEqual(t, second, 0, "outer signatureAlgorithm identifier not found")

	outer := first + 1 + second
	der[outer+12] = 0x0c

	// Guard against a future DER layout change making the mutation a no-op:
	// the corrupt CRL must still fail to parse.
	_, err := parseCRL(der)
	require.Error(t, err, "corrupt CRL must be rejected by Go's parser")

	return der
}

// Seeds CRL distribution point entries into the LDAP server via ldapadd.
func seedLDIF(t *testing.T, ctx context.Context, l *ldapContainer, dn string, lines ...string) {
	t.Helper()

	var b strings.Builder
	fmt.Fprintf(&b, "dn: %s\n", dn)
	fmt.Fprintf(&b, "objectClass: top\n")
	for _, line := range lines {
		b.WriteString(line)
	}
	b.WriteString("\n")

	err := l.container.CopyToContainer(ctx, []byte(b.String()), "/seed.ldif", 0600)
	require.NoError(t, err)

	exitCode, reader, err := l.container.Exec(ctx, []string{
		"ldapadd", "-x",
		"-D", l.rootDN,
		"-w", l.rootPW,
		"-f", "/seed.ldif",
	})
	require.NoError(t, err)
	if exitCode != 0 {
		out, readErr := io.ReadAll(reader)
		require.NoError(t, readErr)
		t.Fatalf("ldapadd failed with exit code %d: %s", exitCode, string(out))
	}
}

func seedLDAPEntries(t *testing.T, ctx context.Context, l *ldapContainer, entries []ldapSeedEntry) {
	t.Helper()

	seedLDIF(t, ctx, l, "dc=example,dc=org",
		"objectClass: dcObject\n",
		"objectClass: organization\n",
		"o: Example Org\n",
		"dc: example\n",
	)

	for _, e := range entries {
		lines := []string{
			"objectClass: cRLDistributionPoint\n",
			fmt.Sprintf("cn: %s\n", e.cn),
		}
		if len(e.crlDER) > 0 {
			lines = append(lines, fmt.Sprintf("certificateRevocationList;binary:: %s\n", base64.StdEncoding.EncodeToString(e.crlDER)))
		}
		seedLDIF(t, ctx, l, e.dn, lines...)
	}
}

// Runs a full collect+emit against a real server entry whose CRL fails to
// process, asserting the single failure status metric is reported.
func collectAndAssertFailureStatus(t *testing.T, uri string, wantStatus int64, reason string) {
	t.Helper()

	state := createTestScrapeState(t)
	crlEntry := newCRL(zaptest.NewLogger(t), state, uri, metadata.AttributeCrlRoleSubject, metadata.AttributeCrlKindBase)

	metrics, err := crlEntry.collect(t.Context())

	require.NoError(t, err)
	require.Error(t, metrics.err)
	assert.Equal(t, wantStatus, metrics.processingStatus)

	rb := state.mb.NewResourceBuilder()
	crlEntry.emit(state.mb, metrics)
	res := rb.Emit()
	md := state.mb.Emit(metadata.WithResource(res))

	require.Equal(t, 1, md.ResourceMetrics().Len())
	metricSlice := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	require.Equal(t, 1, metricSlice.Len(), "%s should only report processing status", reason)
	assert.Equal(t, "pkiengine.crl.processing_status", metricSlice.At(0).Name())

	dp := metricSlice.At(0).Gauge().DataPoints().At(0)
	assert.Equal(t, wantStatus, dp.IntValue())
	assert.Equal(t, uri, requireAttr(t, dp.Attributes(), "crl.uri").Str())
}

func TestLDAPIntegrationTest(t *testing.T) {
	t.Parallel()
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := t.Context()
	ldap, err := startLDAPContainer(t, ctx)
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = ldap.container.Terminate(context.Background())
	})

	crlDER, _ := createTestCrlData(t)
	childCRLDER := createTestCrlForIssuer(t, "Child CA")
	seedLDAPEntries(t, ctx, ldap, []ldapSeedEntry{
		{dn: "CN=Test CA,dc=example,dc=org", cn: "Test CA", crlDER: crlDER},
		// Child of Test CA so one/sub scope searches have a reachable, deeper
		// entry to find (the slapd ACL only exposes cRLDistributionPoint
		// entries to anonymous reads, so the org base itself is not searchable).
		// Its CRL has a distinct issuer so scope tests can prove WHICH entry
		// was returned rather than just that some CRL came back.
		{dn: "CN=Child CA,CN=Test CA,dc=example,dc=org", cn: "Child CA", crlDER: childCRLDER},
		{dn: "CN=No CRL,dc=example,dc=org", cn: "No CRL", crlDER: nil},
		// Serves bytes that pass slapd's CertificateList syntax check but fail
		// Go's x509.ParseRevocationList.
		{dn: "CN=Corrupt CRL,dc=example,dc=org", cn: "Corrupt CRL", crlDER: makeCorruptCrlDER(t)},
	})

	hostPort := net.JoinHostPort(ldap.host, ldap.port)
	timeout := 5 * time.Second
	fetcher := &realCrlFetcher{client: http.DefaultClient}

	t.Run("failure_no_entry", func(t *testing.T) {
		t.Parallel()

		// Subtree search over a readable base with a non-matching filter returns
		// an empty result set instead of an LDAP error. The base must be a
		// cRLDistributionPoint entry: the slapd ACL only exposes those to
		// anonymous reads.
		uri := fmt.Sprintf("ldap://%s/CN=Test CA,dc=example,dc=org?certificateRevocationList?sub?(objectClass=no-such-class)", hostPort)

		fetchable, data, err := fetcher.fetchLDAP(ctx, &realLdapDialer{}, uri, timeout)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "no entry found for DN: CN=Test CA,dc=example,dc=org")
		assert.Equal(t, int64(0), fetchable)
		assert.Nil(t, data)
	})

	t.Run("failure_no_such_object", func(t *testing.T) {
		t.Parallel()

		// A base-scope search on a DN the server cannot find returns a real
		// LDAP noSuchObject error, exercising the retryable "ldap search
		// failed" path that mocks can only fake.
		uri := fmt.Sprintf("ldap://%s/CN=Missing,dc=example,dc=org?certificateRevocationList", hostPort)

		fetchable, data, err := fetcher.fetchLDAP(ctx, &realLdapDialer{}, uri, timeout)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "ldap search failed:")
		assert.True(t, isRetryableFetchError(err), "server errors must be classified as retryable")
		assert.Equal(t, int64(0), fetchable)
		assert.Nil(t, data)
	})

	t.Run("failure_attribute_missing", func(t *testing.T) {
		t.Parallel()

		uri := fmt.Sprintf("ldap://%s/CN=No CRL,dc=example,dc=org?certificateRevocationList", hostPort)

		fetchable, data, err := fetcher.fetchLDAP(ctx, &realLdapDialer{}, uri, timeout)

		require.Error(t, err)
		assert.Contains(t, err.Error(), "attribute not found or is empty: certificateRevocationList;binary")
		assert.Equal(t, int64(0), fetchable)
		assert.Nil(t, data)
	})

	t.Run("collect_emits_fetch_failed_metric", func(t *testing.T) {
		t.Parallel()

		// End-to-end fetch-failure reporting against the real server: the
		// entry exists but carries no CRL, so fetchLDAP returns a permanent
		// error which must surface as the fetch-failed status metric.
		uri := fmt.Sprintf("ldap://%s/CN=No CRL,dc=example,dc=org?certificateRevocationList", hostPort)
		collectAndAssertFailureStatus(t, uri, crlProcessingStatusFetchFailed, "fetch failure")
	})

	t.Run("parse_failure_corrupt_crl", func(t *testing.T) {
		t.Parallel()

		uri := fmt.Sprintf("ldap://%s/CN=Corrupt CRL,dc=example,dc=org?certificateRevocationList", hostPort)
		collectAndAssertFailureStatus(t, uri, crlProcessingStatusParseFailed, "parse failure")
	})

	t.Run("collect_emits_full_crl_metrics", func(t *testing.T) {
		t.Parallel()

		uri := fmt.Sprintf("ldap://%s/CN=Test CA,dc=example,dc=org?certificateRevocationList", hostPort)
		state := createTestScrapeState(t)
		crlEntry := newCRL(zaptest.NewLogger(t), state, uri, metadata.AttributeCrlRoleSubject, metadata.AttributeCrlKindBase)

		metrics, err := crlEntry.collect(ctx)
		require.NoError(t, err)
		require.NoError(t, metrics.err)
		require.Equal(t, crlProcessingStatusSuccess, metrics.processingStatus)

		rb := state.mb.NewResourceBuilder()
		crlEntry.emit(state.mb, metrics)
		res := rb.Emit()
		md := state.mb.Emit(metadata.WithResource(res))
		require.Equal(t, 1, md.ResourceMetrics().Len())

		metricSlice := md.ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
		expected := map[string]func(t *testing.T, val int64){
			"pkiengine.crl.processing_status": func(t *testing.T, val int64) {
				t.Helper()
				assert.Equal(t, crlProcessingStatusSuccess, val)
			},
			"pkiengine.crl.x509.this_update": func(t *testing.T, val int64) {
				t.Helper()
				assert.LessOrEqual(t, val, int64(0), "this_update must be at or before now")
			},
			"pkiengine.crl.x509.next_update": func(t *testing.T, val int64) {
				t.Helper()
				assert.Positive(t, val)
			},
			"pkiengine.crl.x509.revoked_certificates": func(t *testing.T, val int64) {
				t.Helper()
				assert.Equal(t, int64(1), val)
			},
		}
		require.Equal(t, len(expected), metricSlice.Len())

		for i := range metricSlice.Len() {
			metric := metricSlice.At(i)
			validator, ok := expected[metric.Name()]
			require.True(t, ok, "unexpected metric: %q", metric.Name())
			require.Equal(t, 1, metric.Gauge().DataPoints().Len())

			dp := metric.Gauge().DataPoints().At(0)
			assert.Equal(t, uri, requireAttr(t, dp.Attributes(), "crl.uri").Str())
			if metric.Name() != "pkiengine.crl.processing_status" {
				assert.Equal(t, "Test CA", requireAttr(t, dp.Attributes(), "crl.x509.issuer.common_name").Str())
			}
			validator(t, dp.IntValue())
		}
	})

	t.Run("scope_one_search", func(t *testing.T) {
		t.Parallel()

		// The slapd ACL only exposes cRLDistributionPoint entries to anonymous
		// reads, so the search base is the parent entry; the filter pins the
		// one-level search to its single child for a deterministic result.
		uri := fmt.Sprintf("ldap://%s/CN=Test CA,dc=example,dc=org?certificateRevocationList?one?(cn=Child CA)", hostPort)

		fetchable, data, err := fetcher.fetchLDAP(ctx, &realLdapDialer{}, uri, timeout)

		require.NoError(t, err)
		assert.Equal(t, int64(1), fetchable)
		assert.Equal(t, childCRLDER, data, "one-level search should return the Child CA CRL, not the parent's")

		crl, err := parseCRL(data)
		require.NoError(t, err)
		assert.Equal(t, "Child CA", crl.Issuer.CommonName)
	})

	t.Run("scope_sub_search", func(t *testing.T) {
		t.Parallel()

		// Mirror of scope_one_search: the slapd ACL only exposes
		// cRLDistributionPoint entries to anonymous reads, so the search base is
		// the parent entry; the filter pins the subtree search to its single
		// child for a deterministic result.
		uri := fmt.Sprintf("ldap://%s/CN=Test CA,dc=example,dc=org?certificateRevocationList?sub?(cn=Child CA)", hostPort)

		fetchable, data, err := fetcher.fetchLDAP(ctx, &realLdapDialer{}, uri, timeout)

		require.NoError(t, err)
		assert.Equal(t, int64(1), fetchable)
		assert.Equal(t, childCRLDER, data, "subtree search should return the Child CA CRL, not the parent's")

		crl, err := parseCRL(data)
		require.NoError(t, err)
		assert.Equal(t, "Child CA", crl.Issuer.CommonName)
	})
}
