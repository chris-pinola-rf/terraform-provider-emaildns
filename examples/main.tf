terraform {
  required_providers {
    emaildns = {
      source = "registry.terraform.io/hashicorp/emaildns"
    }
  }
}

# =============================================================================
# DMARC Record Validation
# =============================================================================

# Valid DMARC record - will pass validation
data "emaildns_dmarc" "valid" {
  record = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com; ruf=mailto:forensics@example.com; pct=100"
}

output "dmarc_policy" {
  description = "The parsed DMARC policy"
  value       = data.emaildns_dmarc.valid.policy
}

output "dmarc_report_uris" {
  description = "The aggregate report URIs"
  value       = data.emaildns_dmarc.valid.report_uri_aggregate
}

# Example: Using validated record with Cloudflare
# resource "cloudflare_record" "dmarc" {
#   zone_id = var.zone_id
#   name    = "_dmarc"
#   type    = "TXT"
#   content = data.emaildns_dmarc.valid.record
# }

# =============================================================================
# SPF Record Validation
# =============================================================================

# Valid SPF record - will pass validation
data "emaildns_spf" "valid" {
  record = "v=spf1 include:_spf.google.com include:servers.mcsv.net ip4:192.0.2.0/24 ~all"
}

output "spf_mechanisms" {
  description = "The parsed SPF mechanisms"
  value       = data.emaildns_spf.valid.mechanisms
}

output "spf_dns_lookup_count" {
  description = "Number of DNS lookups required (max 10 allowed by RFC)"
  value       = data.emaildns_spf.valid.dns_lookup_count
}

# Example: Using validated record with Cloudflare
# resource "cloudflare_record" "spf" {
#   zone_id = var.zone_id
#   name    = "@"
#   type    = "TXT"
#   content = data.emaildns_spf.valid.record
# }

# =============================================================================
# DKIM Record Validation
# =============================================================================

# Valid DKIM record - will pass validation
# Note: This is a sample RSA public key for demonstration
data "emaildns_dkim" "valid" {
  record = "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDHUigNmWXWQU1xMaOc4Xq1L1Lo8y8qFzqZ6rQNLzb+j3YwjBwEHC9oNWcXqrAqsBgBfJmC7BDL0x6IdCaNEyL3Q3KvQZPksLLzqN5IaMTWYhE7bX4k8HKkAWrJJVaQaXW7/HmAK8Y8htTPxCmKJHQI8V3dWH/JOoq3BlJZu2e22QIDAQAB"
}

output "dkim_key_type" {
  description = "The DKIM key algorithm"
  value       = data.emaildns_dkim.valid.key_type
}

output "dkim_is_revoked" {
  description = "Whether the DKIM key is revoked"
  value       = data.emaildns_dkim.valid.is_revoked
}

# Example: Using validated record with Cloudflare
# resource "cloudflare_record" "dkim" {
#   zone_id = var.zone_id
#   name    = "selector._domainkey"
#   type    = "TXT"
#   content = data.emaildns_dkim.valid.record
# }

# =============================================================================
# Invalid Records - These would cause terraform plan to fail
# =============================================================================

# Uncomment to see validation errors:

# Invalid DMARC - missing required 'p' tag
# data "emaildns_dmarc" "invalid" {
#   record = "v=DMARC1; rua=mailto:dmarc@example.com"
# }

# Invalid DMARC - wrong policy value
# data "emaildns_dmarc" "invalid_policy" {
#   record = "v=DMARC1; p=invalid"
# }

# Invalid SPF - doesn't start with v=spf1
# data "emaildns_spf" "invalid" {
#   record = "include:_spf.google.com ~all"
# }

# Invalid DKIM - invalid base64 in public key
# data "emaildns_dkim" "invalid" {
#   record = "v=DKIM1; k=rsa; p=not-valid-base64!!!"
# }
