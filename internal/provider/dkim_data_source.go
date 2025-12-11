package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ datasource.DataSource                   = &DKIMDataSource{}
	_ datasource.DataSourceWithValidateConfig = &DKIMDataSource{}
)

func NewDKIMDataSource() datasource.DataSource {
	return &DKIMDataSource{}
}

// DKIMDataSource defines the data source implementation.
type DKIMDataSource struct{}

// DKIMDataSourceModel describes the data source data model.
type DKIMDataSourceModel struct {
	Record         types.String `tfsdk:"record"`
	KeyType        types.String `tfsdk:"key_type"`
	PublicKey      types.String `tfsdk:"public_key"`
	HashAlgorithms types.List   `tfsdk:"hash_algorithms"`
	Services       types.List   `tfsdk:"services"`
	Flags          types.List   `tfsdk:"flags"`
	Notes          types.String `tfsdk:"notes"`
	IsRevoked      types.Bool   `tfsdk:"is_revoked"`
}

func (d *DKIMDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dkim"
}

func (d *DKIMDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Validates a DKIM (DomainKeys Identified Mail) DNS TXT record. " +
			"If the record is invalid, terraform plan will fail with a specific error message.",

		Attributes: map[string]schema.Attribute{
			"record": schema.StringAttribute{
				MarkdownDescription: "The DKIM TXT record content to validate (e.g., `v=DKIM1; k=rsa; p=MIGfMA0GCS...`)",
				Required:            true,
			},
			"key_type": schema.StringAttribute{
				MarkdownDescription: "The key algorithm type (rsa or ed25519)",
				Computed:            true,
			},
			"public_key": schema.StringAttribute{
				MarkdownDescription: "The base64-encoded public key",
				Computed:            true,
			},
			"hash_algorithms": schema.ListAttribute{
				MarkdownDescription: "List of acceptable hash algorithms (h tag)",
				Computed:            true,
				ElementType:         types.StringType,
			},
			"services": schema.ListAttribute{
				MarkdownDescription: "List of service types (s tag)",
				Computed:            true,
				ElementType:         types.StringType,
			},
			"flags": schema.ListAttribute{
				MarkdownDescription: "List of flags (t tag, e.g., 'y' for testing, 's' for strict)",
				Computed:            true,
				ElementType:         types.StringType,
			},
			"notes": schema.StringAttribute{
				MarkdownDescription: "Notes field (n tag)",
				Computed:            true,
			},
			"is_revoked": schema.BoolAttribute{
				MarkdownDescription: "True if the key is revoked (empty p= tag)",
				Computed:            true,
			},
		},
	}
}

func (d *DKIMDataSource) ValidateConfig(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var data DKIMDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Skip validation if record is unknown (e.g., depends on another resource)
	if data.Record.IsUnknown() {
		return
	}

	// Validate the DKIM record
	record := data.Record.ValueString()
	_, err := ParseDKIM(record)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid DKIM Record",
			fmt.Sprintf("The DKIM record is malformed: %s\n\nRecord: %s", err.Error(), record),
		)
	}
}

func (d *DKIMDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data DKIMDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	record := data.Record.ValueString()
	parsed, err := ParseDKIM(record)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid DKIM Record",
			fmt.Sprintf("The DKIM record is malformed: %s", err.Error()),
		)
		return
	}

	// Set computed attributes
	data.KeyType = types.StringValue(parsed.KeyType)
	data.IsRevoked = types.BoolValue(parsed.IsRevoked)

	if parsed.PublicKey != "" {
		data.PublicKey = types.StringValue(parsed.PublicKey)
	} else {
		data.PublicKey = types.StringNull()
	}

	if parsed.Notes != "" {
		data.Notes = types.StringValue(parsed.Notes)
	} else {
		data.Notes = types.StringNull()
	}

	// Convert string slices to Terraform lists
	data.HashAlgorithms = convertStringSliceToList(ctx, parsed.HashAlgorithms, &resp.Diagnostics)
	data.Services = convertStringSliceToList(ctx, parsed.Services, &resp.Diagnostics)
	data.Flags = convertStringSliceToList(ctx, parsed.Flags, &resp.Diagnostics)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}
