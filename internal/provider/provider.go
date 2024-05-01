/*
 *  Copyright © 2021-2024 All rights reserved
 *  Maintainer: Ubyon
 */

package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Ubyon/terraform-provider-ubyon/internal/corecfgclient"
)

// Ensure UbyonProvider satisfies various provider interfaces.
var _ provider.Provider = &UbyonProvider{}
var _ provider.ProviderWithFunctions = &UbyonProvider{}

// UbyonProvider defines the provider implementation.
type UbyonProvider struct {
	// version is set to the provider version on release, "dev" when the
	// provider is built and ran locally, and "test" when running acceptance
	// testing.
	version string
}

// UbyonProviderModel describes the provider data model.
type UbyonProviderModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	ApiKey   types.String `tfsdk:"api_key"`
}

func (p *UbyonProvider) Metadata(ctx context.Context, req provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "ubyon"
	resp.Version = p.version
}

func (p *UbyonProvider) Schema(ctx context.Context, req provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Ubyon provider for Terraform.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				MarkdownDescription: "The Ubyon API endpoint. Default https://manage.ubyon.com/api/v1",
				Optional:            true,
			},
			"api_key": schema.StringAttribute{
				MarkdownDescription: "The Ubyon API key.",
				Optional:            true,
			},
		},
	}
}

func (p *UbyonProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data UbyonProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	ep := ConvTypesString(data.Endpoint)
	if len(ep) <= 0 {
		ep = "https://manage.ubyon.com/api/v1/tf"
	}

	acc := &corecfgclient.Configuration{
		BasePath:      ep,
		Host:          "",
		Scheme:        "",
		DefaultHeader: nil,
		UserAgent:     fmt.Sprintf("Ubyon-Terraform-Provider/%s", p.version),
		HTTPClient:    nil,
	}
	apiKey := ConvTypesString(data.ApiKey)
	if len(apiKey) > 0 {
		acc.DefaultHeader = map[string]string{
			"X-UBY-APIKEY": ConvTypesString(data.ApiKey),
		}
	}
	ac := corecfgclient.NewAPIClient(acc)

	// Configuration values are now available.
	// if data.Endpoint.IsNull() { /* ... */ }

	resp.DataSourceData = ac
	resp.ResourceData = ac
}

func (p *UbyonProvider) Resources(ctx context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewAppResource,
		NewSshAppResource,
		NewWebAppResource,
	}
}

func (p *UbyonProvider) DataSources(ctx context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{}
}

func (p *UbyonProvider) Functions(ctx context.Context) []func() function.Function {
	return []func() function.Function{}
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &UbyonProvider{
			version: version,
		}
	}
}
