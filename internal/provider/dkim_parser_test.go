package provider

import (
	"testing"
)

func TestParseDKIM_Valid(t *testing.T) {
	tests := []struct {
		name    string
		record  string
		wantKey string
		wantErr bool
	}{
		{
			name:    "valid RSA key",
			record:  "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHUigNmWXWQU1xMaOc4Xq1L1Lo8y8qFzqZ6rQNLzb+j3YwjBwEHC9oNWcXqrAqsBgBfJmC7BDL0x6IdCaNEyL3Q3KvQZPksLLzqN5IaMTWYhE7bX4k8HKkAWrJJVaQaXW7/HmAK8Y8htTPxCmKJHQI8V3dWH/JOoq3BlJZu2e22QIDAQAB",
			wantKey: "rsa",
			wantErr: false,
		},
		{
			name:    "revoked key (empty p)",
			record:  "v=DKIM1; p=",
			wantKey: "rsa",
			wantErr: false,
		},
		{
			name:    "missing p tag",
			record:  "v=DKIM1; k=rsa",
			wantErr: true,
		},
		{
			name:    "invalid base64",
			record:  "v=DKIM1; p=not-valid-base64!!!",
			wantErr: true,
		},
		{
			name:    "wrong version",
			record:  "v=DKIM2; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHUigNmWXWQU1xMaOc4Xq1L1Lo8y8qFzqZ6rQNLzb+j3YwjBwEHC9oNWcXqrAqsBgBfJmC7BDL0x6IdCaNEyL3Q3KvQZPksLLzqN5IaMTWYhE7bX4k8HKkAWrJJVaQaXW7/HmAK8Y8htTPxCmKJHQI8V3dWH/JOoq3BlJZu2e22QIDAQAB",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, err := ParseDKIM(tt.record)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseDKIM() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr && rec.KeyType != tt.wantKey {
				t.Errorf("ParseDKIM() KeyType = %v, want %v", rec.KeyType, tt.wantKey)
			}
		})
	}
}

func TestParseDKIM_RevokedKey(t *testing.T) {
	rec, err := ParseDKIM("v=DKIM1; p=")
	if err != nil {
		t.Fatalf("ParseDKIM() error = %v", err)
	}
	if !rec.IsRevoked {
		t.Error("ParseDKIM() IsRevoked = false, want true")
	}
}
