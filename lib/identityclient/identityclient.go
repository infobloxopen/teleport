package identityclient

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/gravitational/teleport"
	"github.com/gravitational/trace"
	"github.com/sirupsen/logrus"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

var log = logrus.WithFields(logrus.Fields{
	trace.Component: teleport.ComponentAuth,
})

var (
	shortName = "cert"
)

// Needed for authentication of onprem devices.
const (
	defaultAuthURL = "http://identity-api.identity.svc.cluster.local/v2/session/verify"
	// SSLClientVerifyHeader name of the header set by nginx when request was authenticated by a TLS client certificate.
	SSLClientVerifyHeader = "ssl-client-verify"
	// SSLClientSubjectDNHeader name of the header set by nginx containing the TLS client certificate common name.
	SSLClientSubjectDNHeader = "ssl-client-subject-dn"
	// SSLClientCertSerialNumber ... Serial Number of the client certificate
	SSLClientCertSerialNumber = "ssl-client-serial"
	// SSLClientCert ... Client certificate
	SSLClientCert = "ssl-client-cert"
	// RequestID ... RequestID of request
	RequestID = "Request-Id"
)

// IdentityClient implements an http client to send authentication requests to the Identity service
type IdentityClient struct {
	AuthURL string
	Timeout time.Duration
}

// IdentityClientOption options for NewIdentityClient()
type IdentityClientOption func(c *IdentityClient)

// Verify sends a request to Identity and returns the headers from the response upon success or an error
func (c *IdentityClient) Verify(ctx context.Context, header http.Header) (http.Header, error) {
	hreq, err := http.NewRequest("GET", c.AuthURL, nil)
	if err != nil {
		return nil, err
	}

	hreq.Header = header
	client := &http.Client{Timeout: c.Timeout}

	resp, err := client.Do(hreq)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		body, _ := ioutil.ReadAll(resp.Body)
		return resp.Header, status.Error(codes.Unauthenticated, string(body))
	}
	return resp.Header, nil
}

// NewIdentityClient returns a new IdentityClient with default values
func NewIdentityClient(opts ...IdentityClientOption) *IdentityClient {
	client := &IdentityClient{
		AuthURL: defaultAuthURL,
		Timeout: 3 * time.Second,
	}
	for _, opt := range opts {
		opt(client)
	}
	return client
}

// WithAuthURL sets the AuthURL on the new IdentityClient
func WithAuthURL(authURL string) IdentityClientOption {
	return func(c *IdentityClient) {
		c.AuthURL = authURL
	}
}

// WithTimeout sets the timeout on the new IdentityClient
func WithTimeout(timeout time.Duration) IdentityClientOption {
	return func(c *IdentityClient) {
		c.Timeout = timeout
	}
}

// ValidateIBCertViaCA takes a provisioning ibCert and validate it via CA.
func ValidateIBCertViaCA(IBCert []byte, ibCA *x509.CertPool) error {
	log.Debugln("[ValidateCert] via CA")

	opts := x509.VerifyOptions{
		Roots: ibCA,
	}

	pemBlock, _ := pem.Decode(IBCert)
	if pemBlock == nil {
		return trace.BadParameter("cert: expected PEM-encoded block")
	}

	cert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return err
	}

	if _, err := cert.Verify(opts); err != nil {
		return err
	}

	return nil
}

// ValidateIBCertViaIdentity takes a provisioning ibCert and validate it via identity.
func ValidateIBCertViaIdentity(IBCert []byte, ophid string) error {
	log.Debugf("[ValidateCert] via identity")

	//	iClient := NewIdentityClient(WithAuthURL("http://127.0.0.1:31824/v2/session/verify"))
	iClient := NewIdentityClient()
	ctx := context.Background()

	header := http.Header{}
	//header.Add(iden.RequestID, "teleport-verify")
	header.Add(SSLClientVerifyHeader, "SUCCESS")
	header.Add(SSLClientSubjectDNHeader, "CN="+ophid)
	header.Add(SSLClientCert, strings.Trim(url.Values{shortName: {string(IBCert)}}.Encode(), shortName+"="))

	_, err := iClient.Verify(ctx, header)

	return err
}

// ValidateS2SViaIdentity takes a provisioning S2S and validate it via identity.
func ValidateS2SViaIdentity(jwt string) error {
	log.Debugf("[ValidateS2S] start")

	iClient := NewIdentityClient()
	ctx := context.Background()

	header := http.Header{}
	header.Add("authorization", jwt)

	_, err := iClient.Verify(ctx, header)

	log.Debugf("[ValidateS2S] finish")

	return err
}
