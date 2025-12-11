package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
)

// Ensure EmailDNSProvider satisfies various provider interfaces.
var _ provider.Provider = &EmailDNSProvider{}

// EmailDNSProvider defines the provider implementation.
type EmailDNSProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// EmailDNSProviderModel describes the provider data model.
type EmailDNSProviderModel struct {
	// No configuration needed - this is a validation-only provider
}

func (p *EmailDNSProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "emaildns"
	resp.Version = p.version
}

func (p *EmailDNSProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "The Email DNS provider validates email-related DNS TXT records (DMARC, SPF, DKIM) during the Terraform planning phase. " +
			"This ensures malformed records are caught before they are applied to your DNS provider.",
	}
}

func (p *EmailDNSProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	// No configuration needed - this is a validation-only provider
}

func (p *EmailDNSProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		// No resources - this provider only has data sources
	}
}

func (p *EmailDNSProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewDMARCDataSource,
		NewSPFDataSource,
		NewDKIMDataSource,
	}
}

// New creates a new provider factory function.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &EmailDNSProvider{
			version: version,
		}
	}
}
