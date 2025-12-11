package provider

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ed25519"
)

// DKIMRecord holds the parsed DKIM public key record.
type DKIMRecord struct {
	KeyType        string   // "k" tag - rsa or ed25519, defaults to rsa
	PublicKey      string   // "p" tag - base64 encoded public key
	HashAlgorithms []string // "h" tag - acceptable hash algorithms
	Services       []string // "s" tag - service types
	Flags          []string // "t" tag - flags (y for testing, s for strict)
	Notes          string   // "n" tag - notes
	IsRevoked      bool     // true if p= is empty (key revoked)
}

// ParseDKIM parses a DKIM TXT record and returns the parsed record or an error.
// This is adapted from github.com/emersion/go-msgauth/dkim (MIT licensed).
func ParseDKIM(s string) (*DKIMRecord, error) {
	params, err := parseDKIMParams(s)
	if err != nil {
		return nil, fmt.Errorf("failed to parse DKIM record: %w", err)
	}

	rec := &DKIMRecord{
		KeyType: "rsa", // default
	}

	// Check version if present
	if v, ok := params["v"]; ok && v != "DKIM1" {
		return nil, errors.New("incompatible DKIM version: expected DKIM1")
	}

	// Parse public key (required)
	p, ok := params["p"]
	if !ok {
		return nil, errors.New("missing required 'p' tag (public key)")
	}

	if p == "" {
		// Empty p= means key is revoked
		rec.IsRevoked = true
		rec.PublicKey = ""
	} else {
		// Remove any whitespace from the key
		p = strings.ReplaceAll(p, " ", "")
		rec.PublicKey = p

		// Validate that it's valid base64
		b, err := base64.StdEncoding.DecodeString(p)
		if err != nil {
			return nil, fmt.Errorf("invalid base64 in public key: %w", err)
		}

		// Parse key type
		if k, ok := params["k"]; ok {
			rec.KeyType = k
		}

		// Validate the key based on type
		switch rec.KeyType {
		case "rsa", "":
			rec.KeyType = "rsa"
			// Try to parse as PKIX first, then PKCS1
			pub, err := x509.ParsePKIXPublicKey(b)
			if err != nil {
				pub, err = x509.ParsePKCS1PublicKey(b)
				if err != nil {
					return nil, fmt.Errorf("invalid RSA public key: %w", err)
				}
			}
			rsaPub, ok := pub.(*rsa.PublicKey)
			if !ok {
				return nil, errors.New("public key is not an RSA key")
			}
			// Check minimum key size (RFC 8301 requires at least 1024 bits)
			keyBits := rsaPub.Size() * 8
			if keyBits < 1024 {
				return nil, fmt.Errorf("RSA key too short: %d bits (minimum 1024 required)", keyBits)
			}
		case "ed25519":
			if len(b) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("invalid Ed25519 public key size: got %d bytes, expected %d", len(b), ed25519.PublicKeySize)
			}
		default:
			return nil, fmt.Errorf("unsupported key type: %s (expected rsa or ed25519)", rec.KeyType)
		}
	}

	// Parse hash algorithms (h tag)
	if h, ok := params["h"]; ok {
		rec.HashAlgorithms = parseTagList(h)
	}

	// Parse services (s tag)
	if s, ok := params["s"]; ok {
		rec.Services = parseTagList(s)
	}

	// Parse flags (t tag)
	if t, ok := params["t"]; ok {
		rec.Flags = parseTagList(t)
	}

	// Parse notes (n tag)
	if n, ok := params["n"]; ok {
		rec.Notes = n
	}

	return rec, nil
}

// parseDKIMParams parses the key=value pairs from a DKIM record.
func parseDKIMParams(s string) (map[string]string, error) {
	params := make(map[string]string)
	pairs := strings.Split(s, ";")

	for _, pair := range pairs {
		pair = strings.TrimSpace(pair)
		if pair == "" {
			continue
		}

		idx := strings.Index(pair, "=")
		if idx == -1 {
			return nil, fmt.Errorf("invalid tag format: %q (missing '=')", pair)
		}

		key := strings.TrimSpace(pair[:idx])
		value := strings.TrimSpace(pair[idx+1:])

		if key == "" {
			return nil, errors.New("empty tag name")
		}

		params[key] = value
	}

	return params, nil
}

// parseTagList splits a colon-separated list of values.
func parseTagList(s string) []string {
	parts := strings.Split(s, ":")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}
