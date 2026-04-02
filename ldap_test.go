package pkienginereceiver

import (
	"errors"
	"testing"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/stretchr/testify/assert"
	mock "github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
)

func TestParseLdapUri(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		want     *ldapURI
		wantErr  bool
		errMatch string
	}{
		{
			name:  "Full RFC 4516 URI with Escaped Filter",
			input: "ldap://host:123/ou=People,dc=example,dc=com?sn,givenName?sub?%28objectClass=person%29",
			want: &ldapURI{
				Scheme:     "ldap",
				Host:       "host",
				Port:       "123",
				DN:         "ou=People,dc=example,dc=com",
				Attributes: []string{"sn", "givenName"},
				Scope:      "sub",
				Filter:     "(objectClass=person)",
			},
			wantErr: false,
		},
		{
			name:  "Basic URI (default values)",
			input: "ldap://ldap.example.com/dc=example,dc=com",
			want: &ldapURI{
				Scheme:     "ldap",
				Host:       "ldap.example.com",
				Port:       "",
				DN:         "dc=example,dc=com",
				Attributes: nil,               // Should remain nil
				Scope:      "base",            // Default applied
				Filter:     "(objectClass=*)", // Default applied
				Extensions: nil,               // Should remain nil
			},
			wantErr: false,
		},
		{
			name:     "Malformed URI",
			input:    "ldap://:invalid-port",
			want:     nil,
			wantErr:  true,
			errMatch: "invalid URI format",
		},
		{
			name:     "Invalid Scheme",
			input:    "http://localhost",
			want:     nil,
			wantErr:  true,
			errMatch: "unsupported scheme",
		},
		{
			name:  "LDAPS with DN and Attributes",
			input: "ldaps://example.com/dc=example,dc=com?cn,mail",
			want: &ldapURI{
				Scheme:     "ldaps",
				Host:       "example.com",
				Port:       "",
				DN:         "dc=example,dc=com",
				Attributes: []string{"cn", "mail"},
				Scope:      "base",
				Filter:     "(objectClass=*)",
			},
			wantErr: false,
		},
		{
			name:  "URI with Extensions",
			input: "ldap:///??sub??bindname=cn=Manager%2cdc=example%2cdc=com",
			want: &ldapURI{
				Scheme:     "ldap",
				Host:       "",
				Port:       "",
				DN:         "",
				Scope:      "sub",
				Filter:     "(objectClass=*)",
				Extensions: []string{"bindname=cn=Manager,dc=example,dc=com"},
			},
			wantErr: false,
		},
		{
			name: "Malformed percent encoding in Filter",
			// %ZZ is not a valid hex code
			input:    "ldap://localhost/??sub?%ZZ",
			wantErr:  true,
			errMatch: "failed to decode filter",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got, err := parseLdapUri(tt.input)

			if tt.wantErr {
				require.Error(t, err)
				if tt.errMatch != "" {
					assert.Contains(t, err.Error(), tt.errMatch)
				}
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.want, got)
			}
		})
	}
}

func Test_fetchCrlLdap_Success(t *testing.T) {
	t.Parallel()

	testCRL := []byte("fake_crl_data_123")
	testURI := "ldap://127.0.0.1/CN=Root CA?certificaterevocationlist"
	timeout := time.Second

	mockConn := newMockldapConn(t)
	mockDialer := newMockldapDialer(t)

	mockConn.On("Close").Return(nil).Once()

	fakeResult := &ldap.SearchResult{
		Entries: []*ldap.Entry{{
			Attributes: []*ldap.EntryAttribute{{
				Name:       "certificaterevocationlist;binary",
				ByteValues: [][]byte{testCRL},
			}},
		}},
	}

	mockConn.On("Search", mock.AnythingOfType("*ldap.SearchRequest")).
		Return(fakeResult, nil).
		Once()

	expectedAddr := "ldap://127.0.0.1"
	mockDialer.On("Dial", expectedAddr, timeout).
		Return(mockConn, nil).
		Once()

	crl, _ := createTestCRL(t)
	fetchable, data, err := crl.fetcher.fetchLDAP(t.Context(), mockDialer, testURI, timeout)

	require.NoError(t, err)
	assert.Equal(t, int64(1), fetchable, "fetchable should be 1 on success")
	assert.Equal(t, testCRL, data, "fetched data should match the mocked CRL")
}

func Test_fetchCrlLdap_Dial_Error(t *testing.T) {
	t.Parallel()

	testURI := "ldap://127.0.0.1/CN=Root CA?certificaterevocationlist"

	mockDialer := newMockldapDialer(t)

	dialErr := errors.New("network timeout")
	mockDialer.On("Dial", mock.AnythingOfType("string"), mock.AnythingOfType("time.Duration")).
		Return(nil, dialErr).
		Once()

	crl, _ := createTestCRL(t)
	fetchable, _, err := crl.fetcher.fetchLDAP(t.Context(), mockDialer, testURI, time.Second)

	require.Error(t, err, "expected an error from failed dial")
	require.ErrorContains(t, err, "failed connecting to ldap server:")
	assert.Equal(t, int64(0), fetchable, "fetchable should be 0 on failure")
}

func Test_fetchLDAP_Search_Scenarios(t *testing.T) {
	t.Parallel()

	const (
		testURI      = "ldap://127.0.0.1/CN=Root CA?certificaterevocationlist"
		expectedAddr = "ldap://127.0.0.1"
		timeout      = time.Second
		expectedAttr = "certificaterevocationlist;binary"
	)

	tests := []struct {
		name            string
		setupSearchMock func(*mockldapConn)
		wantErrContains string
	}{
		{
			name: "Search_Error",
			setupSearchMock: func(mockConn *mockldapConn) {
				searchErr := errors.New("ldap error 32: No such object")
				mockConn.On("Search", mock.AnythingOfType("*ldap.SearchRequest")).
					Return((*ldap.SearchResult)(nil), searchErr).
					Once()
			},
			wantErrContains: "ldap search failed:",
		},
		{
			name: "No_Entries_Found",
			setupSearchMock: func(mockConn *mockldapConn) {
				mockConn.On("Search", mock.AnythingOfType("*ldap.SearchRequest")).
					Return(&ldap.SearchResult{Entries: []*ldap.Entry{}}, nil).
					Once()
			},
			wantErrContains: "no entry found for DN: CN=Root CA",
		},
		{
			name: "Empty_Attribute_Value",
			setupSearchMock: func(mockConn *mockldapConn) {
				entry := &ldap.Entry{
					DN:         "CN=Root CA",
					Attributes: []*ldap.EntryAttribute{},
				}

				mockConn.On("Search", mock.AnythingOfType("*ldap.SearchRequest")).
					Return(&ldap.SearchResult{Entries: []*ldap.Entry{entry}}, nil).
					Once()
			},
			wantErrContains: "attribute not found or is empty: " + expectedAttr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			mockConn := newMockldapConn(t)
			mockDialer := newMockldapDialer(t)

			tt.setupSearchMock(mockConn)
			mockConn.On("Close").Return(nil).Once()

			mockDialer.On("Dial", expectedAddr, timeout).Return(mockConn, nil).Once()

			crlEntry, _ := createTestCRL(t)
			fetchable, data, err := crlEntry.fetcher.fetchLDAP(t.Context(), mockDialer, testURI, timeout)

			require.Error(t, err)
			require.ErrorContains(t, err, tt.wantErrContains)
			assert.Equal(t, int64(0), fetchable)
			assert.Nil(t, data)
		})
	}
}
