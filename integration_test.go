package pkienginereceiver

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/terraform-exec/tfexec"
	"github.com/moby/moby/api/types/container"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/golden"
	"github.com/open-telemetry/opentelemetry-collector-contrib/pkg/pdatatest/pmetrictest"
	"github.com/stretchr/testify/require"
	"github.com/stretchr/testify/suite"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/modules/k3s"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
	"go.opentelemetry.io/collector/component/componenttest"
	"go.opentelemetry.io/collector/config/configopaque"
	"go.opentelemetry.io/collector/consumer/consumertest"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/receiver/receivertest"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	authenticationv1 "k8s.io/api/authentication/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	kwait "k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

var update = flag.Bool("update", false, "updates the golden files")
var goldenPathLocks sync.Map
var (
	reNormalizePort = regexp.MustCompile(`http://[^/:]+:\d+`)
	reNormalizeID   = regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)
)

const (
	enginePort   = "8200"
	devRootToken = "dev-root-token"
	saName       = "otel-collector"

	tokenReferencePodImage = "busybox"
	// renovate: datasource=docker depName=rancher/k3s
	k3sImage = "rancher/k3s:v1.37.2-k3s1"
	// renovate: datasource=docker depName=hashicorp/vault
	vaultVersion = "2.2.2"
	// renovate: datasource=docker depName=openbao/openbao
	openBaoVersion        = "2.7.2"
	kubernetesAPIAudience = "https://kubernetes.default.svc"

	testScrapeTimeout      = 15 * time.Second
	testScrapeInterval     = 100 * time.Millisecond
	testCollectionInterval = 200 * time.Millisecond
	testRenewalTimeout     = 60 * time.Second
	testRenewalInterval    = 200 * time.Millisecond
	testTfParallelism      = 100

	// Rate limited requests wait at least one second plus jitter before being
	// re-issued, so a full scrape of the throttled mount takes several seconds.
	testRateLimitTimeout = 120 * time.Second
	// Longer than a throttled scrape,
	// so the rate limit test sees a single scrape.
	testRateLimitCollectionInterval = time.Minute
)

type tfProjectVars struct {
	kubernetes                 bool
	kubernetesCaCrt            string
	kubernetesTokenReviewerJwt string
	jwt                        bool
	jwtIssuer                  string
	jwtValidationPubkeys       string
	jwtAudience                string
	authTokenTTL               int
	authTokenMaxTTL            int
	renewableToken             string
	namespaced                 bool
	numStandalone              int
	numTwoTier                 int
	numLeaf                    int
	rateLimitStandalone        bool
	revocations                bool
}

type authScenario struct {
	name       string
	configFunc func(cfg *config, suite *IntegrationSuite, vars tfProjectVars)
}

type integrationImage struct {
	subtestImageName   string
	repo               string
	envVars            map[string]string
	tags               []string
	runNamespacedTests bool
}

var vaultImage = integrationImage{
	subtestImageName: "vault",
	repo:             "hashicorp/vault",
	envVars: map[string]string{
		"VAULT_DEV_ROOT_TOKEN_ID": devRootToken,
		"VAULT_LOG_LEVEL":         "debug",
	},
	tags: []string{
		vaultVersion,
		// "1.20.4",
		// "1.19.5", // LTS
		// "1.18.5",
		// "1.17.6",
		// "1.16.3", // LTS
		// "1.15.6",
		// "1.14.10",
		// "1.13.13",
	},
}

var openBaoImage = integrationImage{
	subtestImageName: "openbao",
	repo:             "openbao/openbao",
	envVars: map[string]string{
		"BAO_DEV_ROOT_TOKEN_ID": devRootToken,
		"BAO_LOG_LEVEL":         "debug",
	},
	tags: []string{
		openBaoVersion,
		// "2.4.4",
		// "2.3.2",
	},
	runNamespacedTests: true,
}

var integrationMatrixImages = []integrationImage{
	vaultImage,
	openBaoImage,
}

type integrationTestCase struct {
	name          string
	expectedFile  string
	cfgMatchRegex string
	tfVars        tfProjectVars
	auth          authScenario
	// Defaults to testCollectionInterval.
	collectionInterval time.Duration
}

// The canonical auth method used by the golden flight record matrix. Scraped
// metrics are independent of the auth method (it only runs at login), so the
// golden matrix uses the renewable token and the auth method matrix covers the
// remaining methods separately.
var tokenAuth = authScenario{
	name: "token",
	configFunc: func(cfg *config, _ *IntegrationSuite, vars tfProjectVars) {
		cfg.Auth.AuthType = "token"
		cfg.Auth.AuthToken.Token = configopaque.String(vars.renewableToken)
	},
}

type IntegrationSuite struct {
	suite.Suite

	nw                           *testcontainers.DockerNetwork
	k3s                          *k3s.K3sContainer
	longLivedServiceAccountToken string
	kubeCaCrt                    string
	jwtIssuer                    string
	jwtValidationPubkeys         string
	jwtAudience                  string

	// Paths maintained by the suite
	kubeConfigPath string
	boundTokenPath string
}

func (suite *IntegrationSuite) SetupSuite() {
	t := suite.T()
	ctx := t.Context()
	start := time.Now()
	defer func() {
		t.Logf("SetupSuite completed in %s", time.Since(start))
	}()

	// Install the terraform providers while k3s boots.
	tfInitDone := make(chan error, 1)
	go func() {
		_, err := terraformDataDir()
		tfInitDone <- err
	}()
	defer func() {
		require.NoError(t, <-tfInitDone)
	}()

	nw, err := network.New(ctx)
	require.NoError(t, err)
	testcontainers.CleanupNetwork(t, nw)
	suite.nw = nw

	k3sContainer, err := k3s.Run(ctx, k3sImage,
		testcontainers.WithWaitStrategy(wait.ForLog("k3s is up and running")),
		testcontainers.WithCmdArgs(
			// Integration tests only require the kube API (TokenRequest, TokenReview, OIDC/JWKS) plus the controller populating the long-lived service account token secret.
			// Nothing is scheduled, so no node is needed.
			"--disable=local-storage",
			"--disable=metrics-server",
			"--disable=servicelb",
			"--disable=coredns",
			"--disable-cloud-controller",
			"--disable-helm-controller",
			"--disable-agent",
			"--disable-scheduler",
			"--disable-network-policy",
			"--disable-kube-proxy",
			"--egress-selector-mode=disabled",
			// The controller manager starts its informers only once every enabled controller is initialized.
			"--kube-controller-manager-arg=controllers=serviceaccount-token-controller",
		),
		network.WithNetwork([]string{}, nw),
	)
	require.NoError(t, err)
	// Throwaway containers, so skip the graceful stop.
	testcontainers.CleanupContainer(t, k3sContainer, testcontainers.StopTimeout(0))
	suite.k3s = k3sContainer

	kubeConfigYaml, err := k3sContainer.GetKubeConfig(ctx)
	require.NoError(t, err)

	tmpDir := t.TempDir()
	suite.kubeConfigPath = filepath.Join(tmpDir, "kubeconfig.yaml")
	suite.boundTokenPath = filepath.Join(tmpDir, "bound_token.txt")
	err = os.WriteFile(suite.kubeConfigPath, kubeConfigYaml, 0600)
	require.NoError(t, err)

	restCfg, err := clientcmd.RESTConfigFromKubeConfig(kubeConfigYaml)
	require.NoError(t, err)

	k8s, err := kubernetes.NewForConfig(restCfg)
	require.NoError(t, err)

	suite.setupK8sAuthState(t, ctx, k8s, restCfg)
}

func TestIntegrationTestSuite(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}
	t.Parallel()
	suite.Run(t, new(IntegrationSuite))
}

var scrapeMetricsCompareOptions = []pmetrictest.CompareMetricsOption{
	pmetrictest.IgnoreTimestamp(),
	pmetrictest.IgnoreStartTimestamp(),
	pmetrictest.IgnoreResourceMetricsOrder(),
	pmetrictest.IgnoreMetricDataPointsOrder(),
	pmetrictest.IgnoreMetricValues(
		"pkiengine.cert.x509.not_after",
		"pkiengine.cert.x509.not_before",
		"pkiengine.crl.x509.next_update",
		"pkiengine.crl.x509.this_update",
	),
}

//nolint:testifylint // This suite intentionally uses testing subtests so image matrices can run in parallel.
func (suite *IntegrationSuite) TestMatrix() {
	suite.T().Parallel()

	baseVars := suite.baseTFVars()

	for _, img := range integrationMatrixImages {
		for _, tag := range img.tags {
			for _, namespaced := range []bool{false, true} {
				if namespaced && !img.runNamespacedTests {
					continue
				}
				testName := fmt.Sprintf("image=%s/version=%s/namespaced=%t", img.subtestImageName, tag, namespaced)
				suite.T().Run(testName, func(t *testing.T) {
					t.Parallel()
					suite.runCell(t, img, tag, namespaced, baseVars)
				})
			}
		}
	}
}

func (suite *IntegrationSuite) setupK8sAuthState(t *testing.T, ctx context.Context, k8s *kubernetes.Clientset, restCfg *rest.Config) {
	t.Helper()

	ns := "default"
	longLivedToken, secretCACrt := setupK8sAuthResources(t, ctx, k8s, ns)
	suite.longLivedServiceAccountToken = longLivedToken

	tokenRefPod := createTokenBoundReferencePod(t, ctx, k8s, ns, saName)
	boundToken := createBoundServiceAccountToken(t, ctx, k8s, ns, saName, tokenRefPod.Name, tokenRefPod.UID)
	if len(restCfg.CAData) > 0 {
		suite.kubeCaCrt = string(restCfg.CAData)
	} else {
		suite.kubeCaCrt = secretCACrt
	}

	tokenIssuer, audiences, subject := parseJWTClaims(t, boundToken)
	require.Equal(t, fmt.Sprintf("system:serviceaccount:%s:%s", ns, saName), subject, "unexpected bound token subject")
	require.Contains(t, audiences, kubernetesAPIAudience, "bound token audience must include Kubernetes API audience")
	if len(audiences) > 0 {
		suite.jwtAudience = audiences[0]
	}

	restClient := k8s.Discovery().RESTClient()
	openIDConfig := fetchK8sOpenIDConfiguration(t, ctx, restClient)
	suite.jwtIssuer = openIDConfig.Issuer
	require.Equal(t, suite.jwtIssuer, tokenIssuer, "service account token issuer does not match OIDC discovery issuer")

	jwtPubKey := fetchK8sJWTValidationPubkey(t, ctx, restClient, openIDConfig.JWKSURI)
	suite.jwtValidationPubkeys = jwtPubKey

	err := os.WriteFile(suite.boundTokenPath, []byte(boundToken), 0600)
	require.NoError(t, err)
}

func (suite *IntegrationSuite) baseTFVars() tfProjectVars {
	return tfProjectVars{
		kubernetes:                 true,
		kubernetesCaCrt:            suite.kubeCaCrt,
		kubernetesTokenReviewerJwt: suite.longLivedServiceAccountToken,
		jwt:                        true,
		jwtIssuer:                  suite.jwtIssuer,
		jwtValidationPubkeys:       suite.jwtValidationPubkeys,
		jwtAudience:                suite.jwtAudience,
		authTokenTTL:               5,
		authTokenMaxTTL:            30,
		numStandalone:              1,
		numTwoTier:                 1,
		numLeaf:                    1,
		rateLimitStandalone:        false,
		revocations:                true,
	}
}

func (suite *IntegrationSuite) runCell(t *testing.T, img integrationImage, tag string, namespaced bool, baseVars tfProjectVars) {
	t.Helper()

	ctx := t.Context()
	start := time.Now()
	defer func() {
		t.Logf("matrix cell completed in %s", time.Since(start))
	}()

	secretStoreContainer := startSecretStoreContainer(t, ctx, img, tag, suite.nw)

	tf := setupTerraform(t, ctx, t.TempDir(), secretStoreContainer)
	secretStoreAddr := resolveSecretStoreAddress(t, ctx, secretStoreContainer)
	k3dAddr := "https://" + net.JoinHostPort(suite.k3s.GetContainerID()[:12], "6443")

	vars := baseVars
	vars.namespaced = namespaced
	applyTerraform(t, ctx, tf, vars, secretStoreAddr, k3dAddr)
	vars.renewableToken = terraformOutputString(t, ctx, tf, "renewable_token")

	suite.runGoldenMatrix(t, ctx, vars, secretStoreAddr)
	suite.runAuthMatrix(t, ctx, vars, secretStoreAddr)
}

// Starts the secret store engine container for an image/version on the given
// docker network (nil for the default network).
func startSecretStoreContainer(t *testing.T, ctx context.Context, img integrationImage, tag string, nw *testcontainers.DockerNetwork) testcontainers.Container {
	t.Helper()

	imageURI := fmt.Sprintf("%s:%s", img.repo, tag)
	req := testcontainers.ContainerRequest{
		WaitingFor: wait.ForListeningPort(enginePort),
		Image:      imageURI,
		Env:        img.envVars,
		ExposedPorts: []string{
			enginePort,
		},
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.CapAdd = []string{"IPC_LOCK"}
		},
	}
	if nw != nil {
		req.Networks = []string{nw.Name}
	}

	secretStoreContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	require.NoError(t, err)
	testcontainers.CleanupContainer(t, secretStoreContainer, testcontainers.StopTimeout(0))

	return secretStoreContainer
}

func resolveSecretStoreAddress(t *testing.T, ctx context.Context, container testcontainers.Container) string {
	t.Helper()

	host, err := container.Host(ctx)
	require.NoError(t, err)
	natPort, err := container.MappedPort(ctx, "8200/tcp")
	require.NoError(t, err)

	return "http://" + net.JoinHostPort(host, natPort.Port())
}

// Terraform init (provider installation) dominates the setup time of a matrix cell,
// so it runs once per terraform configuration into the user cache and all workspaces share the result through TF_DATA_DIR.
var terraformDataDir = sync.OnceValues(initTerraformDataDir)

func initTerraformDataDir() (string, error) {
	sourceDir := filepath.Join("test", "terraform")
	key, err := terraformConfigHash(sourceDir)
	if err != nil {
		return "", err
	}

	cacheDir, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	baseDir := filepath.Join(cacheDir, "pkienginereceiver")
	dir := filepath.Join(baseDir, "terraform-"+key)
	dataDir := filepath.Join(dir, ".terraform")
	if _, err := os.Stat(dataDir); err == nil {
		return dataDir, nil
	}

	if err := os.MkdirAll(baseDir, 0o750); err != nil {
		return "", err
	}
	tmpDir, err := os.MkdirTemp(baseDir, "init-")
	if err != nil {
		return "", err
	}
	defer func() { _ = os.RemoveAll(tmpDir) }()

	if err := copyTerraformDir(sourceDir, tmpDir); err != nil {
		return "", err
	}
	execPath, err := exec.LookPath("terraform")
	if err != nil {
		return "", fmt.Errorf("terraform binary not found in PATH: %w", err)
	}
	tf, err := tfexec.NewTerraform(tmpDir, execPath)
	if err != nil {
		return "", err
	}
	tf.SetStderr(os.Stderr)
	if err := tf.Init(context.Background(), tfexec.Reconfigure(true)); err != nil {
		return "", fmt.Errorf("terraform init failed: %w", err)
	}

	if err := os.Rename(tmpDir, dir); err != nil {
		if _, statErr := os.Stat(dataDir); statErr != nil {
			return "", err
		}
	}

	// Each data dir holds ~100MB of providers,
	// so drop those of previous configurations.
	stale, err := filepath.Glob(filepath.Join(baseDir, "terraform-*"))
	if err != nil {
		return "", err
	}
	for _, staleDir := range stale {
		if staleDir != dir {
			_ = os.RemoveAll(staleDir)
		}
	}

	return dataDir, nil
}

// Hashes the terraform files so a changed configuration or lock file gets a fresh data dir.
func terraformConfigHash(dir string) (string, error) {
	files, err := terraformFiles(dir)
	if err != nil {
		return "", err
	}

	h := sha256.New()
	for _, name := range files {
		content, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			return "", err
		}
		_, _ = fmt.Fprintf(h, "%s\x00%d\x00", name, len(content))
		h.Write(content)
	}

	return hex.EncodeToString(h.Sum(nil))[:16], nil
}

func setupTerraform(t *testing.T, ctx context.Context, tfDir string, secretStoreContainer testcontainers.Container) *tfexec.Terraform {
	t.Helper()

	dataDir, err := terraformDataDir()
	require.NoError(t, err)

	err = copyTerraformDir(filepath.Join("test", "terraform"), tfDir)
	require.NoError(t, err)

	execPath, err := exec.LookPath("terraform")
	require.NoError(t, err, "terraform binary not found in PATH")

	tf, err := tfexec.NewTerraform(tfDir, execPath)
	require.NoError(t, err)

	// tf.SetStdout(os.Stdout)
	tf.SetStderr(os.Stderr)

	secretStoreAddr := resolveSecretStoreAddress(t, ctx, secretStoreContainer)

	// SetEnv replaces the whole environment,
	// so only pass the bare minimum:
	// PATH for the local-exec provisioners (curl, ...),
	// the shared initialized data dir,
	// plus the secret store connection settings.
	env := map[string]string{
		"PATH":        os.Getenv("PATH"),
		"TF_DATA_DIR": dataDir,
		"VAULT_ADDR":  secretStoreAddr,
		"VAULT_TOKEN": devRootToken,
	}

	err = tf.SetEnv(env)
	require.NoError(t, err)

	return tf
}

func applyTerraform(t *testing.T, ctx context.Context, tf *tfexec.Terraform, vars tfProjectVars, secretStoreAddr, k3dAddr string) {
	t.Helper()

	err := tf.Apply(ctx, terraformApplyOptions(vars, secretStoreAddr, k3dAddr)...)
	require.NoError(t, err, "terraform apply failed")
}

func terraformApplyOptions(vars tfProjectVars, secretStoreAddr, k3dAddr string) []tfexec.ApplyOption {
	return []tfexec.ApplyOption{
		tfexec.Parallelism(testTfParallelism),
		tfexec.Var(fmt.Sprintf("secret_store_host=%s", secretStoreAddr)),
		tfexec.Var(fmt.Sprintf("kubernetes_host=%s", k3dAddr)),
		tfexec.Var(fmt.Sprintf("kubernetes=%t", vars.kubernetes)),
		tfexec.Var(fmt.Sprintf("kubernetes_ca_crt=%s", vars.kubernetesCaCrt)),
		tfexec.Var(fmt.Sprintf("kubernetes_token_reviewer_jwt=%s", vars.kubernetesTokenReviewerJwt)),
		tfexec.Var(fmt.Sprintf("jwt=%t", vars.jwt)),
		tfexec.Var(fmt.Sprintf("jwt_issuer=%s", vars.jwtIssuer)),
		tfexec.Var(fmt.Sprintf("jwt_validation_pubkeys=%s", vars.jwtValidationPubkeys)),
		tfexec.Var(fmt.Sprintf("jwt_audience=%s", vars.jwtAudience)),
		tfexec.Var(fmt.Sprintf("auth_token_ttl=%d", vars.authTokenTTL)),
		tfexec.Var(fmt.Sprintf("auth_token_max_ttl=%d", vars.authTokenMaxTTL)),
		tfexec.Var(fmt.Sprintf("namespaced=%t", vars.namespaced)),
		tfexec.Var(fmt.Sprintf("num_standalone=%d", vars.numStandalone)),
		tfexec.Var(fmt.Sprintf("num_two_tier=%d", vars.numTwoTier)),
		tfexec.Var(fmt.Sprintf("num_leaf=%d", vars.numLeaf)),
		tfexec.Var(fmt.Sprintf("rate_limit_standalone=%t", vars.rateLimitStandalone)),
		tfexec.Var(fmt.Sprintf("revocations=%t", vars.revocations)),
	}
}

func terraformOutputString(t *testing.T, ctx context.Context, tf *tfexec.Terraform, name string) string {
	t.Helper()

	outputs, err := tf.Output(ctx)
	require.NoError(t, err)

	output, ok := outputs[name]
	require.True(t, ok, "missing terraform output %q", name)

	var value string
	err = json.Unmarshal(output.Value, &value)
	require.NoError(t, err)
	require.NotEmpty(t, value)

	return value
}

func startScraperReceiver(t *testing.T, ctx context.Context, suite *IntegrationSuite, tc integrationTestCase, secretStoreAddr string, crlEnabled bool) (*consumertest.MetricsSink, *observer.ObservedLogs, func()) {
	t.Helper()

	// Configure Receiver
	factory := NewFactory()
	cfg := factory.CreateDefaultConfig().(*config)
	cfg.Address = secretStoreAddr

	cfg.MatchRegex = tc.cfgMatchRegex
	cfg.InitialDelay = 0
	cfg.CollectionInterval = testCollectionInterval
	if tc.collectionInterval > 0 {
		cfg.CollectionInterval = tc.collectionInterval
	}
	cfg.Crl.Enabled = crlEnabled
	cfg.Leaf.Enabled = true

	if tc.tfVars.namespaced {
		cfg.Namespace = "tenant-a"
	}

	tc.auth.configFunc(cfg, suite, tc.tfVars)

	err := cfg.validate()
	require.NoError(t, err)

	// Start Receiver
	sink := new(consumertest.MetricsSink)
	core, observedLogs := observer.New(zapcore.DebugLevel)
	logger := zap.New(core)
	settings := receivertest.NewNopSettings(factory.Type())
	settings.Logger = logger
	rcvr, err := factory.CreateMetrics(ctx, settings, cfg, sink)
	require.NoError(t, err)

	err = rcvr.Start(ctx, componenttest.NewNopHost())
	require.NoError(t, err)

	shutdown := func() {
		require.NoError(t, rcvr.Shutdown(ctx))
	}

	return sink, observedLogs, shutdown
}

func assertScrapeMetrics(t *testing.T, sink *consumertest.MetricsSink, expectedFile string, timeout time.Duration, opts ...pmetrictest.CompareMetricsOption) {
	t.Helper()

	expectedPath := filepath.Join("test", "testdata", expectedFile)
	lock := goldenPathLock(expectedPath)
	compareOpts := make([]pmetrictest.CompareMetricsOption, 0, len(scrapeMetricsCompareOptions)+len(opts))
	compareOpts = append(compareOpts, scrapeMetricsCompareOptions...)
	compareOpts = append(compareOpts, opts...)

	if *update {
		require.Eventually(t, func() bool {
			lastMetrics, ok := latestMetricsSnapshot(sink)
			if !ok {
				return false
			}
			normalizeMetrics(lastMetrics)

			lock.Lock()
			err := golden.WriteMetrics(t, expectedPath, lastMetrics)
			lock.Unlock()
			require.NoError(t, err)

			return true
		}, timeout, testScrapeInterval)

		return
	}

	lock.Lock()
	expected, err := golden.ReadMetrics(expectedPath)
	lock.Unlock()
	require.NoError(t, err)
	normalizeMetrics(expected)

	require.Eventually(t, func() bool {
		lastMetrics, ok := latestMetricsSnapshot(sink)
		if !ok {
			return false
		}
		normalizeMetrics(lastMetrics)

		return pmetrictest.CompareMetrics(expected, lastMetrics, compareOpts...) == nil
	}, timeout, testScrapeInterval)
}

func latestMetricsSnapshot(sink *consumertest.MetricsSink) (pmetric.Metrics, bool) {
	allMetrics := sink.AllMetrics()
	if len(allMetrics) == 0 {
		return pmetric.Metrics{}, false
	}

	return allMetrics[len(allMetrics)-1], true
}

func goldenPathLock(path string) *sync.Mutex {
	lock, _ := goldenPathLocks.LoadOrStore(path, &sync.Mutex{})

	return lock.(*sync.Mutex)
}

// Returns the sorted names of the terraform configuration files, templates and the dependency lock file.
func terraformFiles(dir string) ([]string, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var files []string
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() && (strings.HasSuffix(name, ".tf") || strings.HasSuffix(name, ".tfvars") || strings.HasSuffix(name, ".tftpl") || name == ".terraform.lock.hcl") {
			files = append(files, name)
		}
	}

	return files, nil
}

// Copy Terraform files to enable parallel apply.
func copyTerraformDir(src, dst string) error {
	files, err := terraformFiles(src)
	if err != nil {
		return err
	}

	root, err := os.OpenRoot(dst)
	if err != nil {
		return err
	}
	defer func() { _ = root.Close() }()

	for _, name := range files {
		content, err := os.ReadFile(filepath.Join(src, name))
		if err != nil {
			return err
		}
		if err := root.WriteFile(name, content, 0o600); err != nil {
			return err
		}
	}

	return nil
}

func setupK8sAuthResources(t *testing.T, ctx context.Context, k8s *kubernetes.Clientset, ns string) (string, string) {
	t.Helper()

	// Create ServiceAccount
	_, err := k8s.CoreV1().ServiceAccounts(ns).Create(ctx, &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: saName},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	// Create RoleBinding
	_, err = k8s.RbacV1().ClusterRoleBindings().Create(ctx, &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "otel-collector-vault-auth-delegator"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: saName, Namespace: ns}},
		RoleRef:    rbacv1.RoleRef{APIGroup: "rbac.authorization.k8s.io", Kind: "ClusterRole", Name: "system:auth-delegator"},
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	// Create Secret
	secretName := "otel-collector-token"
	_, err = k8s.CoreV1().Secrets(ns).Create(ctx, &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        secretName,
			Annotations: map[string]string{"kubernetes.io/service-account.name": saName},
		},
		Type: corev1.SecretTypeServiceAccountToken,
	}, metav1.CreateOptions{})
	require.NoError(t, err)

	// Wait for Token population
	var longLivedToken string
	var caCrt string
	err = kwait.PollUntilContextTimeout(ctx, 200*time.Millisecond, 10*time.Second, true, func(ctx context.Context) (bool, error) {
		s, err := k8s.CoreV1().Secrets(ns).Get(ctx, secretName, metav1.GetOptions{})
		if err != nil {
			return false, err
		}
		if tData, ok := s.Data["token"]; ok && len(tData) > 0 {
			if caData, ok := s.Data["ca.crt"]; ok && len(caData) > 0 {
				caCrt = string(caData)
			}
			longLivedToken = string(tData)

			return true, nil
		}

		return false, nil
	})
	require.NoErrorf(t, err, "failed to retrieve service account token from secret %q in namespace %q", secretName, ns)
	require.NotEmptyf(t, caCrt, "service account secret %q in namespace %q has empty ca.crt", secretName, ns)

	return longLivedToken, caCrt
}

func createTokenBoundReferencePod(t *testing.T, ctx context.Context, k8s *kubernetes.Clientset, ns, serviceAccountName string) *corev1.Pod {
	t.Helper()

	pod, err := k8s.CoreV1().Pods(ns).Create(ctx, &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name: "token-bound-ref",
		},
		Spec: corev1.PodSpec{
			ServiceAccountName: serviceAccountName,
			NodeName:           "unscheduled",
			Containers: []corev1.Container{
				{
					Name: "ref",
					// This pod is never scheduled, so the image is never pulled or started.
					Image:   tokenReferencePodImage,
					Command: []string{"sh", "-c", "sleep 3600"},
				},
			},
		},
	}, metav1.CreateOptions{})
	require.NoError(t, err)
	require.NotEmpty(t, pod.UID, "token reference pod UID must be set")

	return pod
}

func createBoundServiceAccountToken(
	t *testing.T,
	ctx context.Context,
	k8s *kubernetes.Clientset,
	ns, serviceAccountName, podName string,
	podUID types.UID,
) string {
	t.Helper()

	expirationSeconds := int64(3600)
	tokenReq := &authenticationv1.TokenRequest{
		Spec: authenticationv1.TokenRequestSpec{
			ExpirationSeconds: &expirationSeconds,
			Audiences:         []string{kubernetesAPIAudience},
			BoundObjectRef: &authenticationv1.BoundObjectReference{
				Kind:       "Pod",
				APIVersion: "v1",
				Name:       podName,
				UID:        podUID,
			},
		},
	}

	tokenResp, err := k8s.CoreV1().ServiceAccounts(ns).CreateToken(ctx, serviceAccountName, tokenReq, metav1.CreateOptions{})
	require.NoError(t, err)
	require.NotEmptyf(t, tokenResp.Status.Token, "empty token returned for service account %q in namespace %q", serviceAccountName, ns)

	return tokenResp.Status.Token
}

type jwksResponse struct {
	Keys []jwkKey `json:"keys"`
}

type openIDConfiguration struct {
	Issuer  string `json:"issuer"`
	JWKSURI string `json:"jwks_uri"`
}

type jwkKey struct {
	Kty string `json:"kty"`
	N   string `json:"n"`
	E   string `json:"e"`
}

func parseJWTClaims(t *testing.T, token string) (string, []string, string) {
	t.Helper()

	parts := strings.Split(token, ".")
	require.GreaterOrEqual(t, len(parts), 2)

	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	require.NoError(t, err)

	var claims map[string]any
	err = json.Unmarshal(payload, &claims)
	require.NoError(t, err)

	issuer, _ := claims["iss"].(string)
	subject, _ := claims["sub"].(string)
	audiences := parseJWTAudience(t, claims["aud"])
	require.NotEmpty(t, issuer)

	return issuer, audiences, subject
}

func parseJWTAudience(t *testing.T, raw any) []string {
	t.Helper()

	if v, ok := raw.([]any); ok && len(v) > 0 {
		if s, ok := v[0].(string); ok {
			return []string{s}
		}
	}
	if s, ok := raw.(string); ok {
		return []string{s}
	}

	return nil
}

func fetchK8sOpenIDConfiguration(t *testing.T, ctx context.Context, client rest.Interface) openIDConfiguration {
	t.Helper()

	raw := fetchK8sRaw(t, ctx, client, "/.well-known/openid-configuration")

	var openIDConfig openIDConfiguration
	err := json.Unmarshal(raw, &openIDConfig)
	require.NoError(t, err)
	require.NotEmpty(t, openIDConfig.Issuer)
	require.NotEmpty(t, openIDConfig.JWKSURI)

	return openIDConfig
}

func fetchK8sJWTValidationPubkey(t *testing.T, ctx context.Context, client rest.Interface, jwksURI string) string {
	t.Helper()

	require.NotEmpty(t, jwksURI)

	raw := fetchK8sRaw(t, ctx, client, jwksURI)

	var jwks jwksResponse
	err := json.Unmarshal(raw, &jwks)
	require.NoError(t, err)
	require.Len(t, jwks.Keys, 1)

	return jwkToPEM(t, jwks.Keys[0])
}

func fetchK8sRaw(t *testing.T, ctx context.Context, client rest.Interface, uri string) []byte {
	t.Helper()

	u, err := url.Parse(uri)
	if err == nil && u.IsAbs() {
		uri = u.RequestURI()
	}

	if !strings.HasPrefix(uri, "/") && !strings.HasPrefix(uri, "https://") {
		uri = "/" + uri
	}

	raw, err := client.Get().RequestURI(uri).DoRaw(ctx)
	require.NoError(t, err)

	return raw
}

func jwkToPEM(t *testing.T, key jwkKey) string {
	t.Helper()

	nBytes, err := base64.RawURLEncoding.DecodeString(key.N)
	require.NoError(t, err)
	eBytes, err := base64.RawURLEncoding.DecodeString(key.E)
	require.NoError(t, err)

	n := new(big.Int).SetBytes(nBytes)
	eBig := new(big.Int).SetBytes(eBytes)
	pub := rsa.PublicKey{N: n, E: int(eBig.Int64())}
	der, err := x509.MarshalPKIXPublicKey(&pub)
	require.NoError(t, err)

	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// Normalize metrics to avoid irrelevant changes in diffs.
// E.g. random generated IDs and port numbers.
func normalizeMetrics(metrics pmetric.Metrics) {
	const fixedID = "00000000-0000-0000-0000-000000000000"
	const address = "http://localhost:8200"
	const normalizedNotAfter = int64(123456)
	const normalizedCertSerial = "00:00:00:00:00:00:00:00"

	rms := metrics.ResourceMetrics()
	for i := range rms.Len() {
		rm := rms.At(i)
		if v, ok := rm.Resource().Attributes().Get("engine.address"); ok {
			strVal := v.Str()
			if reNormalizePort.MatchString(strVal) {
				v.SetStr(reNormalizePort.ReplaceAllString(strVal, address))
			}
		}

		sms := rm.ScopeMetrics()
		for j := range sms.Len() {
			sm := sms.At(j)
			ms := sm.Metrics()
			for k := range ms.Len() {
				m := ms.At(k)
				normalizeNotAfter := m.Name() == "pkiengine.cert.x509.not_after"
				var dps pmetric.NumberDataPointSlice
				switch m.Type() {
				case pmetric.MetricTypeGauge:
					dps = m.Gauge().DataPoints()
				case pmetric.MetricTypeSum:
					dps = m.Sum().DataPoints()
				}

				for l := range dps.Len() {
					dp := dps.At(l)
					if normalizeNotAfter && dp.ValueType() == pmetric.NumberDataPointValueTypeInt && dp.IntValue() > 0 {
						dp.SetIntValue(normalizedNotAfter)
					}
					attrs := dp.Attributes()
					if v, ok := attrs.Get("crl.uri"); ok {
						strVal := v.Str()
						strVal = reNormalizePort.ReplaceAllString(strVal, address)
						strVal = reNormalizeID.ReplaceAllString(strVal, fixedID)
						v.SetStr(strVal)
					}
					if v, ok := attrs.Get("issuer.id"); ok {
						strVal := v.Str()
						if reNormalizeID.MatchString(strVal) {
							v.SetStr(fixedID)
						}
					}
					if v, ok := attrs.Get("cert.x509.serial_number"); ok {
						if v.Str() != "" {
							v.SetStr(normalizedCertSerial)
						}
					}
				}
			}
		}
	}
}

// Returns the sum of the int values of the named metric across all data points
// in a snapshot.
func metricValue(metrics pmetric.Metrics, name string) int64 {
	var total int64

	rms := metrics.ResourceMetrics()
	for i := range rms.Len() {
		sms := rms.At(i).ScopeMetrics()
		for j := range sms.Len() {
			ms := sms.At(j).Metrics()
			for k := range ms.Len() {
				m := ms.At(k)
				if m.Name() != name {
					continue
				}

				var dps pmetric.NumberDataPointSlice
				switch m.Type() {
				case pmetric.MetricTypeGauge:
					dps = m.Gauge().DataPoints()
				case pmetric.MetricTypeSum:
					dps = m.Sum().DataPoints()
				}

				for l := range dps.Len() {
					dp := dps.At(l)
					if dp.ValueType() == pmetric.NumberDataPointValueTypeInt {
						total += dp.IntValue()
					}
				}
			}
		}
	}

	return total
}
