package pkienginereceiver

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"net/url"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"
)

const (
	ldapScheme    = "ldap"
	ldapsScheme   = "ldaps"
	ldapScopeBase = "base"
	ldapScopeOne  = "one"
	ldapScopeSub  = "sub"
)

// Components of a parsed LDAP URI.
type ldapURI struct {
	Scheme     string   // ldap, ldaps, ldapi
	Host       string   // hostname or IP
	Port       string   // port number (e.g., "389")
	DN         string   // Distinguished Name (path)
	Attributes []string // List of attributes to retrieve
	Scope      string   // base, one, or sub
	Filter     string   // Search filter
	Extensions []string // Extension strings
}

// Parses a raw LDAP URI string into its components (RFC 4516).
func parseLdapUri(uri string) (*ldapURI, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return nil, fmt.Errorf("invalid URI format: %w", err)
	}

	if u.Scheme != ldapScheme && u.Scheme != ldapsScheme {
		return nil, errors.New("unsupported scheme: must be ldap or ldaps")
	}

	result := &ldapURI{
		Scheme: u.Scheme,
		Host:   u.Hostname(),
		Port:   u.Port(),
	}

	// Extract the DN (Distinguished Name)
	// u.Path comes with a leading slash, e.g., "/dc=example,dc=com"
	path := strings.TrimPrefix(u.Path, "/")
	result.DN = path

	// Parse the LDAP-specific "Query" part.
	// RFC 4516: ?attributes?scope?filter?extensions
	// net/url treats everything after the first '?' as RawQuery.
	// Must split by '?' manually.
	if u.RawQuery == "" {
		// Set defaults if no query is present
		result.Scope = ldapScopeBase
		result.Filter = "(objectClass=*)"

		return result, nil
	}

	parts := strings.Split(u.RawQuery, "?")

	// Part 0: Attributes (comma-separated)
	if len(parts) > 0 && parts[0] != "" {
		attrs := strings.Split(parts[0], ",")
		result.Attributes = attrs
	}

	// Part 1: Scope (base, one, sub)
	if len(parts) > 1 && parts[1] != "" {
		result.Scope = parts[1]
	} else {
		result.Scope = ldapScopeBase // Default per RFC
	}

	// Part 2: Filter
	if len(parts) > 2 && parts[2] != "" {
		// Filters must be URL unescaped (e.g., %28 -> '(')
		decodedFilter, err := url.QueryUnescape(parts[2])
		if err != nil {
			return nil, fmt.Errorf("failed to decode filter: %w", err)
		}
		result.Filter = decodedFilter
	} else {
		result.Filter = "(objectClass=*)" // Default per RFC
	}

	// Part 3: Extensions (comma-separated)
	if len(parts) > 3 && parts[3] != "" {
		exts := strings.Split(parts[3], ",")
		for i, ext := range exts {
			if decoded, err := url.QueryUnescape(ext); err == nil {
				exts[i] = decoded
			}
		}
		result.Extensions = exts
	}

	return result, nil
}

type ldapConn interface {
	Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error)
	Close() error
}

type ldapDialer interface {
	Dial(addr string, timeout time.Duration) (ldapConn, error)
}

var _ ldapConn = (*realLdapConn)(nil)

type realLdapConn struct {
	conn *ldap.Conn
}

func (c *realLdapConn) Search(searchRequest *ldap.SearchRequest) (*ldap.SearchResult, error) {
	return c.conn.Search(searchRequest)
}

func (c *realLdapConn) Close() error {
	return c.conn.Close()
}

var _ ldapDialer = (*realLdapDialer)(nil)

type realLdapDialer struct{}

// Opens an LDAP connection.
func (d *realLdapDialer) Dial(addr string, timeout time.Duration) (ldapConn, error) {
	conn, err := ldap.DialURL(addr, ldap.DialWithDialer(&net.Dialer{Timeout: timeout}))
	if err != nil {
		return nil, err
	}

	return &realLdapConn{conn: conn}, nil
}

type ldapParams struct {
	host      string
	dn        string
	filter    string
	attribute string
	scope     int
}

// Parses an LDAP URI and converts it to validated LDAP search params.
func (f *realCrlFetcher) parseAndPrepare(uri string) (*ldapParams, error) {
	parsed, err := parseLdapUri(uri)
	if err != nil {
		return nil, fmt.Errorf("failed parsing URI: %w", err)
	}

	if len(parsed.Attributes) == 0 {
		return nil, fmt.Errorf("no LDAP object attribute in URI")
	}

	if len(parsed.Attributes) > 1 {
		return nil, fmt.Errorf("got multiple LDAP object attributes in URI, expected 1")
	}

	// https://datatracker.ietf.org/doc/html/rfc4523#section-2.2
	// > Due to changes made to the definition of a CertificateList through
	//   time, no LDAP-specific encoding is defined for this syntax.  Values
	//   of this syntax SHOULD be encoded using DER [X.690] and MUST only be
	//   transferred using the ;binary transfer option [RFC4522]; that is, by
	//   requesting and returning values using attribute descriptions such as
	//   "certificateRevocationList;binary".
	attribute := parsed.Attributes[0]
	if !strings.HasSuffix(attribute, ";binary") {
		attribute += ";binary"
	}

	// Add filter parentheses
	// E.g. needed for AD-CS to prevent filter compile error
	filter := parsed.Filter
	if filter != "" && (!strings.HasPrefix(filter, "(") && !strings.HasSuffix(filter, ")")) {
		filter = fmt.Sprintf("(%s)", filter)
	}

	var ldapHost string
	if parsed.Port == "" {
		ldapHost = fmt.Sprintf("%s://%s", parsed.Scheme, parsed.Host)
	} else {
		ldapHost = fmt.Sprintf("%s://%s:%s", parsed.Scheme, parsed.Host, parsed.Port)
	}

	var scope int
	switch parsed.Scope {
	case ldapScopeBase:
		scope = ldap.ScopeBaseObject
	case ldapScopeOne:
		scope = ldap.ScopeSingleLevel
	case ldapScopeSub:
		scope = ldap.ScopeWholeSubtree
	default:
		return nil, fmt.Errorf("invalid 'scope' parameter value: %s. Valid values are 'base', 'one', or 'sub'", parsed.Scope)
	}

	return &ldapParams{
		host:      ldapHost,
		dn:        parsed.DN,
		filter:    filter,
		attribute: attribute,
		scope:     scope,
	}, nil
}

// Fetches CRL bytes from an LDAP endpoint.
func (f *realCrlFetcher) fetchLDAP(ctx context.Context, dialer ldapDialer, uri string, timeout time.Duration) (int64, []byte, error) {
	var fetchable int64 = 0
	params, err := f.parseAndPrepare(uri)
	if err != nil {
		return fetchable, nil, newPermanentFetchError(fmt.Errorf("failed to parse ldap uri: %w", err))
	}

	// Total timeout is split over dial+search
	start := time.Now()

	// Dial the LDAP server
	conn, err := dialer.Dial(params.host, timeout)
	if err != nil {
		return fetchable, nil, newRetryableFetchError(fmt.Errorf("failed connecting to ldap server: %w", err))
	}
	defer conn.Close() //nolint:errcheck

	if err := ctx.Err(); err != nil {
		return fetchable, nil, err
	}

	elapsed := time.Since(start)
	remaining := timeout - elapsed
	secondsLeft := int(math.Ceil(math.Max(0, remaining.Seconds())))

	searchRequest := ldap.NewSearchRequest(
		params.dn,
		params.scope,
		ldap.DerefAlways,
		0,
		secondsLeft,
		false,
		params.filter,
		[]string{params.attribute},
		nil,
	)

	sr, err := conn.Search(searchRequest)
	if err != nil {
		return fetchable, nil, newRetryableFetchError(fmt.Errorf("ldap search failed: %w", err))
	}

	// Check if any entries were found
	if len(sr.Entries) == 0 {
		return fetchable, nil, newPermanentFetchError(fmt.Errorf("no entry found for DN: %s", params.dn))
	}

	// Extract the CRL data
	crlBytes := sr.Entries[0].GetRawAttributeValue(params.attribute)
	if len(crlBytes) == 0 {
		return fetchable, nil, newPermanentFetchError(fmt.Errorf("attribute not found or is empty: %s", params.attribute))
	}

	fetchable = 1

	return fetchable, crlBytes, nil
}
