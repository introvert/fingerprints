package tlsfp

import "crypto/tls"

// FromClientHelloInfo builds a ClientHello from Go's ClientHelloInfo. It is
// used for the *inner* ClientHello of an accepted ECH connection, which is
// only available decrypted inside crypto/tls. Fields crypto/tls does not
// expose (extension payloads, key shares, ALPS…) are absent.
func FromClientHelloInfo(chi *tls.ClientHelloInfo) *ClientHello {
	ch := &ClientHello{
		Version:            0x0303,
		CipherSuites:       chi.CipherSuites,
		ServerName:         chi.ServerName,
		ALPN:               chi.SupportedProtos,
		SupportedVersions:  chi.SupportedVersions,
		ECPointFormats:     chi.SupportedPoints,
		RawLength:          0,
		CompressionMethods: []uint8{0},
	}
	for _, c := range chi.SupportedCurves {
		ch.SupportedGroups = append(ch.SupportedGroups, uint16(c))
	}
	for _, s := range chi.SignatureSchemes {
		ch.SignatureAlgorithms = append(ch.SignatureAlgorithms, uint16(s))
	}
	for _, id := range chi.Extensions {
		ch.Extensions = append(ch.Extensions, Extension{ID: id, Name: ExtensionName(id)})
	}
	return ch
}
