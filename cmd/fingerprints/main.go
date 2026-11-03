// Command fingerprints runs the browser / TLS fingerprinting server.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"log"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"

	"github.com/introvert/fingerprints/internal/capture"
	"github.com/introvert/fingerprints/internal/server"
	"github.com/introvert/fingerprints/internal/store"
)

func main() {
	var (
		httpsAddr  = flag.String("https", ":8443", "TLS listen address (TLS is terminated here so JA3/JA4/HTTP2 can be captured); empty to disable")
		httpAddr   = flag.String("http", ":8080", "plain HTTP listen address (no TLS fingerprint); empty to disable")
		certFile   = flag.String("cert", "", "TLS certificate (PEM). If empty a self-signed certificate is generated")
		keyFile    = flag.String("key", "", "TLS private key (PEM)")
		hosts      = flag.String("hosts", "localhost,127.0.0.1,::1", "hostnames/IPs for the generated self-signed certificate")
		acmeDomain = flag.String("acme", "", "comma separated domains to obtain Let's Encrypt certificates for (TLS-ALPN-01 on the -https port, must be :443)")
		acmeDir    = flag.String("acme-cache", "acme-cache", "directory for ACME certificates")
		dbPath     = flag.String("db", "fingerprints.db", "SQLite database path; empty disables storage")
		publicURL  = flag.String("public-url", "", "base URL used in permalinks (default: derived from request)")
		trustProxy = flag.Bool("trust-proxy", false, "trust X-Forwarded-For / X-Forwarded-Proto headers")
		adminToken = flag.String("admin-token", os.Getenv("FP_ADMIN_TOKEN"), "token required for listing/related/delete (env FP_ADMIN_TOKEN)")
		readOnly   = flag.Bool("read-only", false, "disable storing new fingerprints")
	)
	flag.Parse()

	var st *store.Store
	if *dbPath != "" {
		if dir := filepath.Dir(*dbPath); dir != "." {
			os.MkdirAll(dir, 0o755)
		}
		var err error
		if st, err = store.Open(*dbPath); err != nil {
			log.Fatalf("open store: %v", err)
		}
		defer st.Close()
	}

	h := server.New(server.Config{
		PublicURL: *publicURL, TrustProxy: *trustProxy, AdminToken: *adminToken, ReadOnly: *readOnly,
	}, st)

	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS10, // accept old clients so we can fingerprint them
		NextProtos: []string{"h2", "http/1.1"},
	}
	switch {
	case *acmeDomain != "":
		m := &autocert.Manager{
			Prompt:     autocert.AcceptTOS,
			HostPolicy: autocert.HostWhitelist(strings.Split(*acmeDomain, ",")...),
			Cache:      autocert.DirCache(*acmeDir),
		}
		tlsCfg.GetCertificate = m.GetCertificate
		tlsCfg.NextProtos = append(tlsCfg.NextProtos, "acme-tls/1")
	case *certFile != "":
		cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
		if err != nil {
			log.Fatalf("load cert: %v", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
	default:
		cert, err := selfSigned(strings.Split(*hosts, ","))
		if err != nil {
			log.Fatalf("self-signed cert: %v", err)
		}
		tlsCfg.Certificates = []tls.Certificate{cert}
		log.Printf("using a generated self-signed certificate for %s", *hosts)
	}

	srv := &capture.Server{Handler: h, TLSConfig: tlsCfg}
	errc := make(chan error, 2)
	if *httpsAddr != "" {
		ln, err := net.Listen("tcp", *httpsAddr)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("HTTPS (TLS + HTTP/2 fingerprinting) on https://%s", ln.Addr())
		go func() { errc <- srv.ServeTLS(ln) }()
	}
	if *httpAddr != "" {
		ln, err := net.Listen("tcp", *httpAddr)
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("HTTP on http://%s", ln.Addr())
		go func() { errc <- srv.ServePlain(ln) }()
	}
	if *httpsAddr == "" && *httpAddr == "" {
		log.Fatal("nothing to listen on")
	}
	log.Fatal(<-errc)
}

func selfSigned(hosts []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "fingerprints self-signed", Organization: []string{"fingerprints"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		h = strings.TrimSpace(h)
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else if h != "" {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}),
	)
}
