package quicfp

import (
	"context"
	"crypto/tls"
	"net"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
)

// Two connections from the same client UDP socket must each get their own
// fingerprint (and the second connection must not inherit the first).
func TestSocketReuse(t *testing.T) {
	ts := httptest.NewUnstartedServer(nil)
	ts.StartTLS()
	cert := ts.TLS.Certificates[0]
	ts.Close()

	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	table := NewTable()
	srvTr := &quic.Transport{Conn: &TeeConn{PacketConn: pc, Table: table}}
	ln, err := srvTr.Listen(&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"fp"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept(context.Background())
			if err != nil {
				return
			}
			_ = c
		}
	}()

	cpc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cpc.Close()
	cliTr := &quic.Transport{Conn: cpc}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, sni := range []string{"one.test", "two.test"} {
		c, err := cliTr.Dial(ctx, pc.LocalAddr(), &tls.Config{ServerName: sni, InsecureSkipVerify: true, NextProtos: []string{"fp"}}, nil)
		if err != nil {
			t.Fatal(err)
		}
		time.Sleep(50 * time.Millisecond)
		fp := table.Lookup(cpc.LocalAddr().String())
		if fp == nil || fp.TLS == nil || fp.TLS.ClientHello.ServerName != sni {
			t.Fatalf("after dialing %s: fingerprint %+v", sni, fp)
		}
		c.CloseWithError(0, "")
	}
}
