---
page_title: "Provider: emaildns"
description: |-
  The emaildns provider validates email-related DNS TXT records (DMARC, SPF, DKIM) during Terraform's planning phase.
---

# emaildns Provider

The emaildns provider validates email-related DNS TXT records during Terraform's planning phase, catching malformed records **before** they're applied to your DNS provider.

This provider is **DNS provider-agnostic** - use it alongside Cloudflare, Route53, Azure DNS, or any other DNS provider to ensure your email authentication records are valid.

## Why Use This Provider?

Email authentication records (DMARC, SPF, DKIM) have strict syntax requirements. A typo or invalid value can:

- Break email delivery
- Cause authentication failures
- Take time to propagate fixes via DNS TTLs

This provider catches these errors at `terraform plan` time, before any changes are applied.

## Example Usage

```hcl
terraform {
  required_providers {
    emaildns = {
      source  = "chris-pinola-rf/emaildns"
      version = "~> 0.1"
    }
    cloudflare = {
      source  = "cloudflare/cloudflare"
      version = "~> 4.0"
    }
  }
}

# Validate DMARC record before creating it
data "emaildns_dmarc" "main" {
  record = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
}

# Use the validated record with your DNS provider
resource "cloudflare_record" "dmarc" {
  zone_id = var.zone_id
  name    = "_dmarc"
  type    = "TXT"
  content = data.emaildns_dmarc.main.record
}
```

## Supported Record Types

| Data Source | Purpose |
|-------------|---------|
| [emaildns_dmarc](data-sources/dmarc.md) | Validate DMARC records (RFC 7489) |
| [emaildns_spf](data-sources/spf.md) | Validate SPF records (RFC 7208) |
| [emaildns_dkim](data-sources/dkim.md) | Validate DKIM public key records (RFC 6376) |

## Validation Behavior

When a record is invalid, `terraform plan` fails with a specific error message:

```
Error: Invalid DMARC Record

  The DMARC record is malformed: invalid policy for parameter 'p'

  Record: v=DMARC1; p=rejectt; rua=mailto:dmarc@example.com
```

This prevents invalid records from ever being applied to your DNS.
