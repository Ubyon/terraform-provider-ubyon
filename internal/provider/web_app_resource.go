/*
 *  Copyright © 2021-2024 All rights reserved
 *  Maintainer: Ubyon
 */

package provider

import (
	"context"
	"fmt"
	"net/http"
	"strconv"

	"github.com/hashicorp/terraform-plugin-framework-validators/int64validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/Ubyon/terraform-provider-ubyon/internal/corecfgclient"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &WebAppResource{}
var _ resource.ResourceWithImportState = &WebAppResource{}

func NewWebAppResource() resource.Resource {
	return &WebAppResource{}
}

// WebAppResource defines the resource implementation.
type WebAppResource struct {
	//client     *http.Client
	appsApiSvc *corecfgclient.AppsApiService
}

// WebAppResourceModel describes the resource data model.
type WebAppResourceModel struct {
	// The Id of the app
	Id types.String `tfsdk:"id"`
	// The name of the app
	Name types.String `tfsdk:"name"`
	// The description for the app
	Description types.String `tfsdk:"description"`

	// The app authentication is enabled or not (True/False)
	IsAuthnEnabled types.Bool `tfsdk:"is_authn_enabled"`
	// The manager of the cloud resource NONE ManagedByNone AWS ManagedByAws AZURE ManagedByAzure GCP ManagedByGcp SNOWFLAKE ManagedBySnowflake DATABRICKS ManagedByDatabricks
	ManagedBy types.String `tfsdk:"managed_by"`
	// The resource the AuthProvider manages (UBYON/ENTERPRISE) UBYON ResourceTypeUbyon ENTERPRISE ResourceTypeEnterprise CLOUD ResourceTypeCloud
	ResourceType types.String `tfsdk:"resource_type"`
	// The Type of the app (PUBLIC|PRIVATE|SHORTCUT) PUBLIC WebAppPublic PRIVATE WebAppPrivate SHORTCUT WebAppShortcut
	AppType types.String `tfsdk:"app_type"`

	Addr types.String `tfsdk:"addr"`
	Port types.Int64  `tfsdk:"port"`
	// The layer4 / layer7 protocol of the app endpoint port HTTPS AppEndpointProtocolHTTPS HTTP AppEndpointProtocolHTTP
	Protocol   types.String          `tfsdk:"protocol"`
	BaSettings BrowserAccessSettings `tfsdk:"browser_access_settings"`
	//StartUri   types.String          `tfsdk:"start_uri"`
	// The Id of the app endpoint
	AppEndpointId types.String `tfsdk:"app_endpoint_id"`

	NetworkId       types.String       `tfsdk:"network_id"`
	ConnectorIds    []types.String     `tfsdk:"connector_ids"`
	AuthProviderIds []types.String     `tfsdk:"auth_provider_ids"`
	AppLaunchpadId  types.String       `tfsdk:"app_launchpad_id"`
	SecretsStores   []*AppSecretsStore `tfsdk:"secrets_stores"`
	AppTagIds       []types.String     `tfsdk:"app_tag_ids"`
}

func (ar *WebAppResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_web_app"
}

func (ar *WebAppResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Resource schema for WebApp",
		Attributes: map[string]schema.Attribute{

			"id": &schema.StringAttribute{
				Required:    false,
				Computed:    true,
				Optional:    false,
				Description: "The Id of the app",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"name": &schema.StringAttribute{
				Required:    true,
				Optional:    false,
				Description: "The name of the app",
			},
			"description": &schema.StringAttribute{
				Optional:    true,
				Description: "The description for the app",
				Default:     stringdefault.StaticString(""),
				Computed:    true,
			},
			"resource_type": &schema.StringAttribute{
				Optional:    true,
				Description: "The resource the AuthProvider manages",
				Validators: []validator.String{
					stringvalidator.OneOf(
						"UBYON",
						"ENTERPRISE",
						"CLOUD",
					),
				},
				Default:  stringdefault.StaticString("ENTERPRISE"),
				Computed: true,
			},
			"app_type": &schema.StringAttribute{
				Optional:    true,
				Description: "The Type of the app",
				Validators: []validator.String{
					stringvalidator.OneOf(
						"PUBLIC",
						"PRIVATE",
					),
				},
				Computed: true,
				Default:  stringdefault.StaticString("PRIVATE"),
			},
			"is_authn_enabled": &schema.BoolAttribute{
				Optional:    true,
				Description: "The app authentication is enabled or not",
				Default:     booldefault.StaticBool(false),
				Computed:    true,
			},
			"managed_by": &schema.StringAttribute{
				Optional:    true,
				Description: "The manager of the cloud resource",
				Validators: []validator.String{
					stringvalidator.OneOf(
						"NONE",
						"AWS",
						"AZURE",
						"GCP",
						"SNOWFLAKE",
						"DATABRICKS",
					),
				},
				Computed: true,
				Default:  stringdefault.StaticString("NONE"),
			},
			"addr": &schema.StringAttribute{
				Optional:    true,
				Description: "The address in either IPAddress or FQDN format",
			},
			"port": &schema.Int64Attribute{
				Optional:    true,
				Description: "The port number",
				Validators: []validator.Int64{
					int64validator.Between(1, 65535),
				},
			},
			"protocol": &schema.StringAttribute{
				Required:    true,
				Optional:    false,
				Description: "The layer4 / layer7 protocol of the app endpoint port",
				Validators: []validator.String{
					stringvalidator.OneOf(
						"HTTPS",
						"HTTP",
					),
				},
			},
			"browser_access_settings": &schema.SingleNestedAttribute{
				Optional:    true,
				Description: "The browser access settings for an appendpoint",
				Attributes: map[string]schema.Attribute{
					/*"id": &schema.StringAttribute{
						Required:    false,
						Optional:    false,
						Computed:    true,
						Description: "The Id of the browser access settings",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.UseStateForUnknown(),
						},
					},*/
					"app_endpoint_id": &schema.StringAttribute{
						Required:    false,
						Optional:    false,
						Computed:    true,
						Description: "The Id of the appendpoint",
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.UseStateForUnknown(),
						},
					},
					"port": &schema.Int64Attribute{
						Optional:    true,
						Computed:    true,
						Description: "The port on which the server is listening on",
					},
					"url_alias": &schema.BoolAttribute{
						Optional:    true,
						Computed:    true,
						Description: "Enable/Disable URL alias for the application",
						PlanModifiers: []planmodifier.Bool{
							boolplanmodifier.UseStateForUnknown(),
						},
					},
					"hosting_type": &schema.StringAttribute{
						Optional:    true,
						Description: "Hosting type for the application settings",
						Validators: []validator.String{
							stringvalidator.OneOf(
								"UBYON",
								"ENTERPRISE",
							),
						},
					},
					"resource_type": &schema.StringAttribute{
						Optional:    true,
						Computed:    true,
						Description: "The resource type of the app",
						Validators: []validator.String{
							stringvalidator.OneOf(
								"UBYON",
								"ENTERPRISE",
							),
						},
						PlanModifiers: []planmodifier.String{
							stringplanmodifier.UseStateForUnknown(),
						},
					},
					"url_alias_settings": &schema.SingleNestedAttribute{
						Optional:    true,
						Description: "The settings to enable URL alias for the application",
						Attributes: map[string]schema.Attribute{
							"cert_id": &schema.StringAttribute{
								Optional:    true,
								Description: "Id of the certificate which matches with the CNAME domain",
							},
							"cname": &schema.StringAttribute{
								Optional:    true,
								Description: "CNAME associated with the domain",
							},
						},
					},
					"http_attributes": &schema.SingleNestedAttribute{
						Optional:    true,
						Description: "The http attributes required for browser access",
						Attributes: map[string]schema.Attribute{
							"headers": &schema.MapAttribute{
								Optional:    true,
								Description: "The headers required for browser access",
								ElementType: types.ListType{ElemType: types.StringType},
							},
							"start_uri": &schema.StringAttribute{
								Optional:    true,
								Description: "The Uri to redirect the users after entering the application",
							},
						},
					},
					"https_attributes": &schema.SingleNestedAttribute{
						Optional:    true,
						Description: "The https attributes required for browser access",
						Attributes: map[string]schema.Attribute{
							"headers": &schema.MapAttribute{
								Optional:    true,
								Description: "The headers required for browser access",
								ElementType: types.ListType{ElemType: types.StringType},
							},
							"start_uri": &schema.StringAttribute{
								Optional:    true,
								Description: "The Uri to redirect the users after entering the application",
							},
						},
					},
					/*"ssh_attributes": &schema.SingleNestedAttribute{
						Optional:    true,
						Description: "The ssh attributes required for browser access",
						Attributes: map[string]schema.Attribute{
							"max_connections": &schema.Int64Attribute{
								Optional:    true,
								Description: "Maximum number of concurrent SSH connections",
							},
							"start_uri": &schema.StringAttribute{
								Optional:    true,
								Description: "The Uri to redirect the users after entering the application",
							},
						},
					},*/
				},
			},
			/*"start_uri": &schema.StringAttribute{
				Optional:    true,
				Description: "The Uri to redirect the users after entering the application",
			},*/
			"app_endpoint_id": &schema.StringAttribute{
				Computed:    true,
				Optional:    false,
				Required:    false,
				Description: "The Id of the app endpoint",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"app_launchpad_id": &schema.StringAttribute{
				Optional:    true,
				Description: "The Id of the app launchpad",
			},
			"network_id": &schema.StringAttribute{
				Optional:    true,
				Description: "The Id of the app network",
			},
			"connector_ids": &schema.ListAttribute{
				Optional:    true,
				Description: "The Ids of the app connectors",
				ElementType: types.StringType,
			},
			"auth_provider_ids": &schema.ListAttribute{
				Optional:    true,
				Description: "The Ids of the app auth providers",
				ElementType: types.StringType,
			},
			"secrets_stores": &schema.ListNestedAttribute{
				Optional:    true,
				Description: "The app secrets store",
				NestedObject: schema.NestedAttributeObject{
					CustomType:    nil,
					Validators:    nil,
					PlanModifiers: nil,
					Attributes: map[string]schema.Attribute{
						"app_id": &schema.StringAttribute{
							Optional:    true,
							Description: "The Id of the app to which the secretsstore is associated",
						},
						"attributes": &schema.SingleNestedAttribute{
							Optional:    true,
							Description: "The format of attributes for WebApp-SecretsStore association",
							Attributes: map[string]schema.Attribute{
								"credential_type": &schema.StringAttribute{
									Optional:    true,
									Description: "The credentials of the app-secretsstore association",
								},
								"principal_scope": &schema.StringAttribute{
									Optional:    true,
									Description: "The scope of secret store usage by the principals",
								},
							},
						},
						"secrets_store_id": &schema.StringAttribute{
							Optional:    true,
							Description: "The Id of a secret store",
						},
					},
				},
			},
			"app_tag_ids": &schema.ListAttribute{
				Optional:    true,
				Description: "The Ids of the app tags",
				ElementType: types.StringType,
			},
		},
	}
}

func (ar *WebAppResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	// Prevent panic if the provider has not been configured.
	if req.ProviderData == nil {
		return
	}

	ac, ok := req.ProviderData.(*corecfgclient.APIClient)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf("Expected *http.Client, got: %T. Please report this issue to the provider developers.", req.ProviderData),
		)

		return
	}

	ar.appsApiSvc = ac.AppsApi
}

func convWebAppToAppResourceModel(webApp *WebAppResourceModel, app *AppResourceModel) {
	app.Id = webApp.Id
	app.Name = webApp.Name
	app.Description = webApp.Description
	app.Category = types.StringValue("SERVICE")
	app.IsAuthnEnabled = webApp.IsAuthnEnabled
	app.ManagedBy = types.StringValue("NONE")
	app.ResourceType = webApp.ResourceType
	app.ServiceType = types.StringValue("NONE")
	app.SubCategory = types.StringValue("WEB")
	app.AppType = webApp.AppType

	ep := &AppEndpointRaw{
		Endpoint: AppEndpoint{
			AccessType: types.StringValue("BROWSER"),
			Addr: &AppEndpointAddr{
				Value: webApp.Addr,
				//Type_: String{},
			},
			Attributes:     nil,
			AppEndpointId:  webApp.AppEndpointId,
			OnboardingType: types.StringValue("MANUAL"),
			Port: &AppEndpointPort{
				Type_: types.StringValue("INDIVIDUAL"),
				Value: types.StringValue(fmt.Sprintf("%d", ConvTypesInt64(webApp.Port))),
			},
			Protocol: webApp.Protocol,
			Source:   types.StringValue("MANUAL"),
			//ServiceTemplateId: nil,
		},
		BaSettings: &webApp.BaSettings,
	}
	if IsIpStr(ConvTypesString(webApp.Addr)) {
		ep.Endpoint.Addr.Type_ = types.StringValue("IP")
	} else {
		ep.Endpoint.Addr.Type_ = types.StringValue("FQDN")
	}
	switch ConvTypesString(webApp.Protocol) {
	case "HTTPS":
		if webApp.BaSettings.BaHttpsAttribs != nil &&
			!IsTypesStringEmpty(webApp.BaSettings.BaHttpsAttribs.StartUri) {
			ep.Endpoint.Attributes = &AppEndpointAttributes{
				DefaultAttributes: &AppEndpointDefaultAttributes{
					StartUri: webApp.BaSettings.BaHttpsAttribs.StartUri,
				},
			}
		}
	case "HTTP":
		if webApp.BaSettings.BaHttpAttribs != nil &&
			!IsTypesStringEmpty(webApp.BaSettings.BaHttpAttribs.StartUri) {
			ep.Endpoint.Attributes = &AppEndpointAttributes{
				DefaultAttributes: &AppEndpointDefaultAttributes{
					StartUri: webApp.BaSettings.BaHttpAttribs.StartUri,
				},
			}
		}
	}
	app.Endpoints = []*AppEndpointRaw{ep}

	if !IsTypesStringEmpty(webApp.NetworkId) {
		app.NetworkIds = []types.String{webApp.NetworkId}
	}
	app.ConnectorIds = webApp.ConnectorIds
	app.AuthProviderIds = webApp.AuthProviderIds
	if !IsTypesStringEmpty(webApp.AppLaunchpadId) {
		app.AppLaunchpadIds = []types.String{webApp.AppLaunchpadId}
	}
	app.SecretsStores = webApp.SecretsStores
	app.AppTagIds = webApp.AppTagIds
}

func convAppToWebAppResourceModel(ctx context.Context,
	app *AppResourceModel, webApp *WebAppResourceModel) (err error) {

	webApp.Id = app.Id
	webApp.Name = app.Name
	webApp.Description = app.Description
	webApp.IsAuthnEnabled = app.IsAuthnEnabled
	webApp.ManagedBy = app.ManagedBy
	webApp.ResourceType = app.ResourceType
	webApp.AppType = app.AppType

	if len(app.Endpoints) > 0 && app.Endpoints[0] != nil {
		ep := app.Endpoints[0]
		if ep.Endpoint.Addr != nil {
			webApp.Addr = ep.Endpoint.Addr.Value
		}
		if ep.Endpoint.Port != nil {
			var portInt64 int64
			portInt64, err = strconv.ParseInt(ConvTypesString(ep.Endpoint.Port.Value), 10, 64)
			if err == nil {
				webApp.Port = types.Int64Value(portInt64)
			} else {
				tflog.Trace(ctx, fmt.Sprintf("err %v converting %s",
					err, ConvTypesString(ep.Endpoint.Port.Value)))
			}
		}
		webApp.Protocol = ep.Endpoint.Protocol
		if ep.BaSettings != nil {
			webApp.BaSettings = *ep.BaSettings
		}
		if ep.Endpoint.Attributes != nil &&
			ep.Endpoint.Attributes.DefaultAttributes != nil {
			//webApp.StartUri = ep.Endpoint.Attributes.DefaultAttributes.StartUri
		}
		webApp.AppEndpointId = ep.Endpoint.AppEndpointId
	}
	if len(app.NetworkIds) > 0 {
		webApp.NetworkId = app.NetworkIds[0]
	}
	webApp.ConnectorIds = app.ConnectorIds
	webApp.AuthProviderIds = app.AuthProviderIds
	if len(app.AppLaunchpadIds) > 0 {
		webApp.AppLaunchpadId = app.AppLaunchpadIds[0]
	}
	webApp.SecretsStores = app.SecretsStores
	webApp.AppTagIds = app.AppTagIds
	return
}

func (ar *WebAppResource) Create(ctx context.Context,
	req resource.CreateRequest, resp *resource.CreateResponse) {

	var data WebAppResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	var appData AppResourceModel
	convWebAppToAppResourceModel(&data, &appData)
	if !appCreateHelper(ctx, req, resp, &appData, ar.appsApiSvc) {
		return
	}

	convAppToWebAppResourceModel(ctx, &appData, &data)

	// Write logs using the tflog package
	// Documentation: https://terraform.io/plugin/log
	tflog.Trace(ctx, "created a web app resource")

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (ar *WebAppResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var curr, data WebAppResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &curr)...)

	if resp.Diagnostics.HasError() {
		return
	}

	//resp.Diagnostics.AddWarning("curr web data", spewCfg.Sdump(curr))

	appId := ConvTypesString(curr.Id)
	if len(appId) <= 0 {
		resp.Diagnostics.AddError("WebApp id nil", fmt.Sprintf("%v", curr))
		return
	}

	var currAppData, appData AppResourceModel
	appData.Id = curr.Id

	convWebAppToAppResourceModel(&curr, &currAppData)
	if !appReadHelper(ctx, req, resp, appId, &currAppData, &appData, ar.appsApiSvc) {
		return
	}
	convAppToWebAppResourceModel(ctx, &appData, &data)

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (ar *WebAppResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var curr, data WebAppResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Read Terraform current data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &curr)...)
	if resp.Diagnostics.HasError() {
		return
	}

	var currApp, planApp AppResourceModel
	convWebAppToAppResourceModel(&data, &planApp)
	convWebAppToAppResourceModel(&curr, &currApp)
	if !appUpdateHelper(ctx, req, resp, &currApp, &planApp, ar.appsApiSvc) {
		return
	}
	convAppToWebAppResourceModel(ctx, &planApp, &data)

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (ar *WebAppResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data WebAppResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	appId := ConvTypesString(data.Id)
	if len(appId) <= 0 {
		resp.Diagnostics.AddError("Web App id nil", fmt.Sprintf("%v", data))
		return
	}

	httpResp, err := ar.appsApiSvc.DeleteApp(ctx, appId)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to delete app, got error: %s", err))
		return
	}
	if httpResp == nil {
		resp.Diagnostics.AddError("unexpected response from API", fmt.Sprintf("%v", httpResp))
		return
	}
	if httpResp.StatusCode != http.StatusNoContent {
		resp.Diagnostics.AddError("unexpected response from API. Got an unexpected response code %v", fmt.Sprintf("%d", httpResp.StatusCode))
		return
	}
}

func (ar *WebAppResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
