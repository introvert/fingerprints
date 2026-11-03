package tlsfp

import (
	"crypto/tls"
	"fmt"
)

// IsGREASE reports whether v is a GREASE value (RFC 8701).
func IsGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && v>>8 == v&0xff
}

var extensionNames = map[uint16]string{
	0: "server_name", 1: "max_fragment_length", 2: "client_certificate_url", 3: "trusted_ca_keys",
	4: "truncated_hmac", 5: "status_request", 6: "user_mapping", 7: "client_authz", 8: "server_authz",
	9: "cert_type", 10: "supported_groups", 11: "ec_point_formats", 12: "srp", 13: "signature_algorithms",
	14: "use_srtp", 15: "heartbeat", 16: "application_layer_protocol_negotiation",
	17: "status_request_v2", 18: "signed_certificate_timestamp", 19: "client_certificate_type",
	20: "server_certificate_type", 21: "padding", 22: "encrypt_then_mac", 23: "extended_master_secret",
	24: "token_binding", 25: "cached_info", 27: "compress_certificate", 28: "record_size_limit",
	34: "delegated_credentials", 35: "session_ticket", 41: "pre_shared_key", 42: "early_data",
	43: "supported_versions", 44: "cookie", 45: "psk_key_exchange_modes", 47: "certificate_authorities",
	48: "oid_filters", 49: "post_handshake_auth", 50: "signature_algorithms_cert", 51: "key_share",
	57: "quic_transport_parameters", 17513: "application_settings_old", 17613: "application_settings",
	30031: "channel_id_old", 30032: "channel_id", 65037: "encrypted_client_hello", 65281: "renegotiation_info",
}

var groupNames = map[uint16]string{
	1: "sect163k1", 23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 29: "x25519", 30: "x448",
	256: "ffdhe2048", 257: "ffdhe3072", 258: "ffdhe4096", 259: "ffdhe6144", 260: "ffdhe8192",
	512: "MLKEM512", 513: "MLKEM768", 514: "MLKEM1024",
	4587: "SecP256r1MLKEM768", 4588: "X25519MLKEM768", 4589: "SecP384r1MLKEM1024",
	25497: "X25519Kyber768Draft00", 25498: "SecP256r1Kyber768Draft00",
}

var sigAlgNames = map[uint16]string{
	0x0201: "rsa_pkcs1_sha1", 0x0203: "ecdsa_sha1", 0x0401: "rsa_pkcs1_sha256", 0x0403: "ecdsa_secp256r1_sha256",
	0x0501: "rsa_pkcs1_sha384", 0x0503: "ecdsa_secp384r1_sha384", 0x0601: "rsa_pkcs1_sha512",
	0x0603: "ecdsa_secp521r1_sha512", 0x0804: "rsa_pss_rsae_sha256", 0x0805: "rsa_pss_rsae_sha384",
	0x0806: "rsa_pss_rsae_sha512", 0x0807: "ed25519", 0x0808: "ed448", 0x0809: "rsa_pss_pss_sha256",
	0x080a: "rsa_pss_pss_sha384", 0x080b: "rsa_pss_pss_sha512", 0x0402: "dsa_sha256", 0x0302: "dsa_sha224",
	0x0202: "dsa_sha1", 0x0301: "rsa_sha224", 0x0303: "ecdsa_sha224", 0x0502: "dsa_sha384", 0x0602: "dsa_sha512",
	0x081a: "ecdsa_brainpoolP256r1tls13_sha256", 0x081b: "ecdsa_brainpoolP384r1tls13_sha384",
	0x081c: "ecdsa_brainpoolP512r1tls13_sha512", 0x0904: "mldsa44", 0x0905: "mldsa65", 0x0906: "mldsa87",
}

var versionNames = map[uint16]string{
	0x0002: "SSL 2.0", 0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2",
	0x0304: "TLS 1.3", 0xfeff: "DTLS 1.0", 0xfefd: "DTLS 1.2", 0xfefc: "DTLS 1.3",
}

var certCompressionNames = map[uint16]string{1: "zlib", 2: "brotli", 3: "zstd"}

var pskModeNames = map[uint8]string{0: "psk_ke", 1: "psk_dhe_ke"}

func lookup(m map[uint16]string, v uint16) string {
	if IsGREASE(v) {
		return "GREASE"
	}
	if n, ok := m[v]; ok {
		return n
	}
	return fmt.Sprintf("unknown(0x%04x)", v)
}

// ExtensionName returns a human readable extension name.
func ExtensionName(v uint16) string { return lookup(extensionNames, v) }

// GroupName returns a human readable named group.
func GroupName(v uint16) string { return lookup(groupNames, v) }

// SigAlgName returns a human readable signature scheme name.
func SigAlgName(v uint16) string { return lookup(sigAlgNames, v) }

// VersionName returns a human readable protocol version.
func VersionName(v uint16) string { return lookup(versionNames, v) }

// CipherName returns the IANA cipher suite name.
func CipherName(v uint16) string {
	if IsGREASE(v) {
		return "GREASE"
	}
	switch v {
	case 0x00ff:
		return "TLS_EMPTY_RENEGOTIATION_INFO_SCSV"
	case 0x5600:
		return "TLS_FALLBACK_SCSV"
	}
	n := tls.CipherSuiteName(v)
	if len(n) > 2 && n[:2] == "0x" {
		return fmt.Sprintf("unknown(0x%04x)", v)
	}
	return n
}
