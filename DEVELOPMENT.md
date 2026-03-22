# Intro
This project aims to fill the blind spots of important PKI metrics which are not exposed by the telemetry endpoint of the secret store ([OpenBao](https://openbao.org/docs/internals/telemetry/) | [Vault](https://developer.hashicorp.com/vault/docs/internals/telemetry)).

# Testing
To run unit tests:
```terminal
just test-short
```

To run unit + integration tests:
```terminal
just test-long
```

The flight recorder integration tests approach with [testcontainers](https://golang.testcontainers.org/) of upstream contrib is used.
After making changes run `just update-golden` to update the recorded files.

The integration tests use containers to run a test matrix for:
- Secret stores and different versions
- Authentication methods and renewal
- Namespaced true/false
- Metric scenarios

A single K3S container is used and shared between the testcases to verify the Kubernetes and JWT auth methods.

## Compatibility
OpenBao aims to be API compatible with Vault.
The Vault Go SDK and Terraform provider are used to interact with OpenBao.

Both Vault and OpenBao officially support only the latest public version. Note that Vault Enterprise offers LTS versions, but these are not available for public testing.

- https://endoflife.date/hashicorp-vault
- https://endoflife.date/openbao

# Concurrency
Processing speed is mainly limited by the speed of network requests.

To manage system load, a fixed-size worker pool executes mount, issuer and CRL tasks. The concurrency limit configures the worker count and therefore the maximum number of concurrent network operations. Tasks can enqueue follow-up work (mounts enqueue issuers, issuers enqueue CRLs).

CRL fetch requests are protected by a [singleflight](https://pkg.go.dev/golang.org/x/sync/singleflight) group to prevent thundering herds.

The metric builder is not concurrency-safe and requires a lock during operation. Resource attributes are scrape-scoped (`engine.address`, `engine.namespace`) while `engine.mount` is carried as a metric attribute on mount-scoped metrics to support scrape-global error metrics.
The Terraform variables `num_two_tier`, `num_standalone` and `num_leaf` can be adjusted to test different deployment sizes. It's recommended to use a mount per issuer ([reference](https://developer.hashicorp.com/vault/docs/secrets/pki/considerations#one-ca-certificate-one-secrets-engine)), however this is not enforced.

# CRL
## Caching
Optionally, a shared in-memory LRU cache is reused across scrape runs to avoid repeated downloads and parsing of CRLs. Within a single scrape run, each unique CRL URI is normally checked over the network at most once, additional fetches can occur on cache-eviction recovery paths.

LDAP CRLs are cached only within the current scrape run.

For HTTP:
1. Within a single scrape, each CRL URI is fetched at most once and then reused from cache.
2. The cache persists across scrape runs.
3. On the next scrape HTTP CRLs are revalidated:
   - Send `If-None-Match` if a cached `ETag` exists.
   - Send `If-Modified-Since` if a cached timestamp exists.
   - If neither exists, do a full `GET`.
4. Response handling:
   - `304 Not Modified`: keep cached CRL data; update cached `ETag` / `Last-Modified` if present.
   - `200 OK`: replace cached data and validators.
5. Timestamp source precedence on `200 OK`: `Last-Modified` first, `Date` as fallback.

## LDAP
LDAP CDP URIs aren't supported by OpenBao.
Vault supports LDAP URIs ([PR](https://github.com/hashicorp/vault/pull/26477)).

Although LDAP is less common for CRLs these days, it's still commonly used in Windows Active Directory Certificate Services and EJBCA deployments.

LDAP is not integration tested but instead mocked via [mockery](https://vektra.github.io/mockery/) due to the lack of maintained LDAP container images that support configurable object classes and anonymous access.

The LDAP package used ([go-ldap/ldap/v3](https://pkg.go.dev/github.com/go-ldap/ldap/v3)), doesn't support propagating Go Context ([#326](https://github.com/go-ldap/ldap/issues/326)/[#551](https://github.com/go-ldap/ldap/issues/551)). The config value of `crl.timeout` is shared between `net.Dialer` (DNS resolving, local binding and connecting) and `ldap.conn.Search`, the latter only supports full seconds which requires the leftover time of the dialer to be rounded up for the search operation.

# Other notes:
- The `sys/health` endpoint, which provides the cluster name and cluster version, cannot be called from within namespaces.
- The secret stores support rate-limiting, however there is no client side implementation based on the [optionally](https://developer.hashicorp.com/vault/api-docs/system/quotas-config#enable_rate_limit_response_headers) returned headers in the SDK besides passing a [`*rate.Limiter`](https://pkg.go.dev/github.com/hashicorp/vault-client-go#WithRateLimiter).
- OpenBao supports Delta CRLs but is not yet fully configurable (tested with v2.5.0). Vault supports configuring Delta CRLs ([PR](https://github.com/hashicorp/vault/pull/30319)).
- Tracking CRL fetch duration could be interesting but can be misleading with the current caching and retrying logic.
