package provider

import (
	"context"
	"fmt"

	"github.com/emersion/go-msgauth/dmarc"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ datasource.DataSource              = &DMARCDataSource{}
	_ datasource.DataSourceWithValidateConfig = &DMARCDataSource{}
)

func NewDMARCDataSource() datasource.DataSource {
	return &DMARCDataSource{}
}

// DMARCDataSource defines the data source implementation.
type DMARCDataSource struct{}

// DMARCDataSourceModel describes the data source data model.
type DMARCDataSourceModel struct {
	Record             types.String `tfsdk:"record"`
	Policy             types.String `tfsdk:"policy"`
	SubdomainPolicy    types.String `tfsdk:"subdomain_policy"`
	DKIMAlignment      types.String `tfsdk:"dkim_alignment"`
	SPFAlignment       types.String `tfsdk:"spf_alignment"`
	Percent            types.Int64  `tfsdk:"percent"`
	ReportURIAggregate types.List   `tfsdk:"report_uri_aggregate"`
	ReportURIFailure   types.List   `tfsdk:"report_uri_failure"`
}

func (d *DMARCDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_dmarc"
}

func (d *DMARCDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Validates a DMARC (Domain-based Message Authentication, Reporting, and Conformance) DNS TXT record. " +
			"If the record is invalid, terraform plan will fail with a specific error message.",

		Attributes: map[string]schema.Attribute{
			"record": schema.StringAttribute{
				MarkdownDescription: "The DMARC TXT record content to validate (e.g., `v=DMARC1; p=reject; rua=mailto:dmarc@example.com`)",
				Required:            true,
			},
			"policy": schema.StringAttribute{
				MarkdownDescription: "The parsed policy value (none, quarantine, or reject)",
				Computed:            true,
			},
			"subdomain_policy": schema.StringAttribute{
				MarkdownDescription: "The parsed subdomain policy value (sp tag)",
				Computed:            true,
			},
			"dkim_alignment": schema.StringAttribute{
				MarkdownDescription: "The DKIM alignment mode (r for relaxed, s for strict)",
				Computed:            true,
			},
			"spf_alignment": schema.StringAttribute{
				MarkdownDescription: "The SPF alignment mode (r for relaxed, s for strict)",
				Computed:            true,
			},
			"percent": schema.Int64Attribute{
				MarkdownDescription: "The percentage of messages to which the policy applies (0-100)",
				Computed:            true,
			},
			"report_uri_aggregate": schema.ListAttribute{
				MarkdownDescription: "List of URIs for aggregate reports (rua tag)",
				Computed:            true,
				ElementType:         types.StringType,
			},
			"report_uri_failure": schema.ListAttribute{
				MarkdownDescription: "List of URIs for failure reports (ruf tag)",
				Computed:            true,
				ElementType:         types.StringType,
			},
		},
	}
}

func (d *DMARCDataSource) ValidateConfig(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var data DMARCDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Skip validation if record is unknown (e.g., depends on another resource)
	if data.Record.IsUnknown() {
		return
	}

	// Validate the DMARC record
	record := data.Record.ValueString()
	_, err := dmarc.Parse(record)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid DMARC Record",
			fmt.Sprintf("The DMARC record is malformed: %s\n\nRecord: %s", err.Error(), record),
		)
	}
}

func (d *DMARCDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data DMARCDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	record := data.Record.ValueString()
	parsed, err := dmarc.Parse(record)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid DMARC Record",
			fmt.Sprintf("The DMARC record is malformed: %s", err.Error()),
		)
		return
	}

	// Set computed attributes
	data.Policy = types.StringValue(string(parsed.Policy))

	if parsed.SubdomainPolicy != "" {
		data.SubdomainPolicy = types.StringValue(string(parsed.SubdomainPolicy))
	} else {
		data.SubdomainPolicy = types.StringNull()
	}

	data.DKIMAlignment = types.StringValue(string(parsed.DKIMAlignment))
	data.SPFAlignment = types.StringValue(string(parsed.SPFAlignment))

	if parsed.Percent != nil {
		data.Percent = types.Int64Value(int64(*parsed.Percent))
	} else {
		data.Percent = types.Int64Null()
	}

	// Convert string slices to Terraform lists
	data.ReportURIAggregate = convertStringSliceToList(ctx, parsed.ReportURIAggregate, &resp.Diagnostics)
	data.ReportURIFailure = convertStringSliceToList(ctx, parsed.ReportURIFailure, &resp.Diagnostics)

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// convertStringSliceToList converts a Go string slice to a Terraform list.
func convertStringSliceToList(ctx context.Context, slice []string, diags *diag.Diagnostics) types.List {
	if len(slice) == 0 {
		return types.ListNull(types.StringType)
	}

	elements := make([]types.String, len(slice))
	for i, s := range slice {
		elements[i] = types.StringValue(s)
	}

	list, d := types.ListValueFrom(ctx, types.StringType, elements)
	diags.Append(d...)
	return list
}
