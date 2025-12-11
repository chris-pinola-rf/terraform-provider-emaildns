package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/wttw/spf"
)

// Ensure provider defined types fully satisfy framework interfaces.
var (
	_ datasource.DataSource                   = &SPFDataSource{}
	_ datasource.DataSourceWithValidateConfig = &SPFDataSource{}
)

func NewSPFDataSource() datasource.DataSource {
	return &SPFDataSource{}
}

// SPFDataSource defines the data source implementation.
type SPFDataSource struct{}

// SPFDataSourceModel describes the data source data model.
type SPFDataSourceModel struct {
	Record         types.String `tfsdk:"record"`
	Mechanisms     types.List   `tfsdk:"mechanisms"`
	Redirect       types.String `tfsdk:"redirect"`
	DNSLookupCount types.Int64  `tfsdk:"dns_lookup_count"`
}

// mechanismObjectType defines the Terraform object type for SPF mechanisms.
var mechanismObjectType = types.ObjectType{
	AttrTypes: map[string]attr.Type{
		"qualifier": types.StringType,
		"type":      types.StringType,
		"value":     types.StringType,
	},
}

func (d *SPFDataSource) Metadata(ctx context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_spf"
}

func (d *SPFDataSource) Schema(ctx context.Context, req datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Validates an SPF (Sender Policy Framework) DNS TXT record. " +
			"If the record is invalid, terraform plan will fail with a specific error message.",

		Attributes: map[string]schema.Attribute{
			"record": schema.StringAttribute{
				MarkdownDescription: "The SPF TXT record content to validate (e.g., `v=spf1 include:_spf.google.com ~all`)",
				Required:            true,
			},
			"mechanisms": schema.ListNestedAttribute{
				MarkdownDescription: "List of parsed SPF mechanisms",
				Computed:            true,
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"qualifier": schema.StringAttribute{
							MarkdownDescription: "The qualifier (+ for pass, - for fail, ~ for softfail, ? for neutral)",
							Computed:            true,
						},
						"type": schema.StringAttribute{
							MarkdownDescription: "The mechanism type (all, include, a, mx, ip4, ip6, exists, ptr)",
							Computed:            true,
						},
						"value": schema.StringAttribute{
							MarkdownDescription: "The mechanism value (domain, IP range, etc.)",
							Computed:            true,
						},
					},
				},
			},
			"redirect": schema.StringAttribute{
				MarkdownDescription: "The redirect modifier value, if present",
				Computed:            true,
			},
			"dns_lookup_count": schema.Int64Attribute{
				MarkdownDescription: "Number of mechanisms that require DNS lookups (SPF allows max 10)",
				Computed:            true,
			},
		},
	}
}

func (d *SPFDataSource) ValidateConfig(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var data SPFDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Skip validation if record is unknown (e.g., depends on another resource)
	if data.Record.IsUnknown() {
		return
	}

	// Validate the SPF record
	record := data.Record.ValueString()
	_, err := spf.ParseSPF(record)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid SPF Record",
			fmt.Sprintf("The SPF record is malformed: %s\n\nRecord: %s", err.Error(), record),
		)
	}
}

func (d *SPFDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var data SPFDataSourceModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	record := data.Record.ValueString()
	parsed, err := spf.ParseSPF(record)
	if err != nil {
		resp.Diagnostics.AddError(
			"Invalid SPF Record",
			fmt.Sprintf("The SPF record is malformed: %s", err.Error()),
		)
		return
	}

	// Count DNS lookup mechanisms
	dnsLookupCount := 0
	mechanismValues := make([]attr.Value, 0, len(parsed.Mechanisms))

	for _, m := range parsed.Mechanisms {
		qualifier, mechType, value := parseMechanism(m)

		// Count mechanisms that require DNS lookups
		switch mechType {
		case "include", "a", "mx", "ptr", "exists":
			dnsLookupCount++
		}

		mechObj, diags := types.ObjectValue(
			mechanismObjectType.AttrTypes,
			map[string]attr.Value{
				"qualifier": types.StringValue(qualifier),
				"type":      types.StringValue(mechType),
				"value":     types.StringValue(value),
			},
		)
		resp.Diagnostics.Append(diags...)
		mechanismValues = append(mechanismValues, mechObj)
	}

	// Include redirect in DNS lookup count
	if parsed.Redirect != "" {
		dnsLookupCount++
	}

	mechList, diags := types.ListValue(mechanismObjectType, mechanismValues)
	resp.Diagnostics.Append(diags...)
	data.Mechanisms = mechList

	if parsed.Redirect != "" {
		data.Redirect = types.StringValue(parsed.Redirect)
	} else {
		data.Redirect = types.StringNull()
	}

	data.DNSLookupCount = types.Int64Value(int64(dnsLookupCount))

	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

// parseMechanism extracts the qualifier, type, and value from an SPF mechanism.
func parseMechanism(m spf.Mechanism) (qualifier, mechType, value string) {
	str := m.String()

	// Default qualifier is pass (+)
	qualifier = "+"

	// Check for explicit qualifier
	if len(str) > 0 {
		switch str[0] {
		case '+':
			qualifier = "+"
			str = str[1:]
		case '-':
			qualifier = "-"
			str = str[1:]
		case '~':
			qualifier = "~"
			str = str[1:]
		case '?':
			qualifier = "?"
			str = str[1:]
		}
	}

	// Extract type and value based on mechanism type
	switch m := m.(type) {
	case spf.MechanismAll:
		return qualifier, "all", ""
	case spf.MechanismInclude:
		return qualifier, "include", m.DomainSpec
	case spf.MechanismA:
		return qualifier, "a", formatMechanismA(m)
	case spf.MechanismMX:
		return qualifier, "mx", formatMechanismMX(m)
	case spf.MechanismIp4:
		return qualifier, "ip4", m.Net.String()
	case spf.MechanismIp6:
		return qualifier, "ip6", m.Net.String()
	case spf.MechanismExists:
		return qualifier, "exists", m.DomainSpec
	case spf.MechanismPTR:
		return qualifier, "ptr", m.DomainSpec
	default:
		// Fallback: parse from string representation
		return qualifier, "unknown", str
	}
}

func formatMechanismA(m spf.MechanismA) string {
	if m.DomainSpec == "" {
		return ""
	}
	return m.DomainSpec
}

func formatMechanismMX(m spf.MechanismMX) string {
	if m.DomainSpec == "" {
		return ""
	}
	return m.DomainSpec
}
