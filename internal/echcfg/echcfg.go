// Package echcfg creates and persists an Encrypted Client Hello (ECH)
// configuration for the server, so clients that support ECH can be
// fingerprinted on their real (inner) ClientHello.
package echcfg

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
)

const (
	kemX25519  = 0x0020 // DHKEM(X25519, HKDF-SHA256)
	kdfSHA256  = 0x0001
	aeadAES128 = 0x0001
	aeadChaCha = 0x0003
	echVersion = 0xfe0d
	maxNameLen = 0
)

// Key is a persisted ECH key.
type Key struct {
	ConfigID   uint8  `json:"config_id"`
	PublicName string `json:"public_name"`
	PrivateKey []byte `json:"private_key"`
}

// Config returns the encoded ECHConfig for k.
func (k *Key) Config() ([]byte, error) {
	priv, err := ecdh.X25519().NewPrivateKey(k.PrivateKey)
	if err != nil {
		return nil, err
	}
	if len(k.PublicName) == 0 || len(k.PublicName) > 255 {
		return nil, errors.New("echcfg: public name must be 1..255 bytes")
	}
	pub := priv.PublicKey().Bytes()
	var c []byte
	c = append(c, k.ConfigID)
	c = binary.BigEndian.AppendUint16(c, kemX25519)
	c = binary.BigEndian.AppendUint16(c, uint16(len(pub)))
	c = append(c, pub...)
	suites := []uint16{kdfSHA256, aeadAES128, kdfSHA256, aeadChaCha}
	c = binary.BigEndian.AppendUint16(c, uint16(2*len(suites)))
	for _, v := range suites {
		c = binary.BigEndian.AppendUint16(c, v)
	}
	c = append(c, maxNameLen, byte(len(k.PublicName)))
	c = append(c, k.PublicName...)
	c = binary.BigEndian.AppendUint16(c, 0) // no extensions
	out := binary.BigEndian.AppendUint16(nil, echVersion)
	out = binary.BigEndian.AppendUint16(out, uint16(len(c)))
	return append(out, c...), nil
}

// ConfigList returns the ECHConfigList (what goes in the DNS HTTPS record).
func (k *Key) ConfigList() ([]byte, error) {
	cfg, err := k.Config()
	if err != nil {
		return nil, err
	}
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(cfg))), cfg...), nil
}

// TLSKey returns the key in crypto/tls form.
func (k *Key) TLSKey() (tls.EncryptedClientHelloKey, error) {
	cfg, err := k.Config()
	if err != nil {
		return tls.EncryptedClientHelloKey{}, err
	}
	return tls.EncryptedClientHelloKey{Config: cfg, PrivateKey: k.PrivateKey, SendAsRetry: true}, nil
}

// HTTPSRecord renders an example DNS HTTPS record advertising the config.
func (k *Key) HTTPSRecord(host string, port string) string {
	list, _ := k.ConfigList()
	rec := host + `. 300 IN HTTPS 1 . alpn="h3,h2"`
	if port != "" && port != "443" {
		rec += " port=" + port
	}
	return rec + " ech=" + base64.StdEncoding.EncodeToString(list)
}

// LoadOrCreate reads the key from path, creating it if missing. An empty
// path creates an ephemeral key.
func LoadOrCreate(path, publicName string) (*Key, error) {
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			var k Key
			if err := json.Unmarshal(b, &k); err != nil {
				return nil, err
			}
			if publicName != "" && k.PublicName != publicName {
				k.PublicName = publicName
			}
			return &k, nil
		}
	}
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	id := make([]byte, 1)
	rand.Read(id)
	k := &Key{ConfigID: id[0], PublicName: publicName, PrivateKey: priv.Bytes()}
	if path != "" {
		b, _ := json.MarshalIndent(k, "", "  ")
		if err := os.WriteFile(path, b, 0o600); err != nil {
			return nil, err
		}
	}
	return k, nil
}
