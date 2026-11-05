package tlsfp

import (
	"crypto/tls"
	"net/http/httptest"
	"testing"
)

func testCert(t *testing.T) tls.Certificate {
	t.Helper()
	ts := httptest.NewUnstartedServer(nil)
	ts.StartTLS()
	defer ts.Close()
	return ts.TLS.Certificates[0]
}
