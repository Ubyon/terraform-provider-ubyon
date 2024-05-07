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
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	"github.com/Ubyon/terraform-provider-ubyon/internal/corecfgclient"
)

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &SshAppResource{}
var _ resource.ResourceWithImportState = &SshAppResource{}

func NewSshAppResource() resource.Resource {
	return &SshAppResource{}
}

// SshAppResource defines the resource implementation.
type SshAppResource struct {
	appsApiSvc *corecfgclient.AppsApiService
}

// SshAppResourceModel describes the resource data model.
type SshAppResourceModel struct {
	// The Id of the app
	Id types.String `tfsdk:"id"`
	// The name of the app
	Name types.String `tfsdk:"name"`
	// The description for the app
	Description types.String `tfsdk:"description"`

	// The resource the AuthProvider manages (UBYON/ENTERPRISE) UBYON ResourceTypeUbyon ENTERPRISE ResourceTypeEnterprise CLOUD ResourceTypeCloud
	ResourceType types.String `tfsdk:"resource_type"`
	// The Type of the app (PUBLIC|PRIVATE|SHORTCUT) PUBLIC SshAppPublic PRIVATE SshAppPrivate SHORTCUT SshAppShortcut
	AppType types.String `tfsdk:"app_type"`

	Addr       types.String             `tfsdk:"addr"`
	Port       types.Int64              `tfsdk:"port"`
	Attributes AppEndpointSSHAttributes `tfsdk:"attributes"`
	// The Id of the app endpoint
	AppEndpointId types.String `tfsdk:"app_endpoint_id"`

	NetworkId       types.String       `tfsdk:"network_id"`
	ConnectorIds    []types.String     `tfsdk:"connector_ids"`
	AuthProviderIds []types.String     `tfsdk:"auth_provider_ids"`
	AppLaunchpadId  types.String       `tfsdk:"app_launchpad_id"`
	SecretsStores   []*AppSecretsStore `tfsdk:"secrets_stores"`
	AppTagIds       []types.String     `tfsdk:"app_tag_ids"`
}

func (ar *SshAppResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_ssh_app"
}

func (ar *SshAppResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Resource schema for SshApp",
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
			"attributes": &schema.SingleNestedAttribute{
				Optional:    true,
				Description: "The request format of ssh Attributes of an AppEndpoint",
				Attributes: map[string]schema.Attribute{
					"ub_client": &schema.StringAttribute{
						Optional:    true,
						Description: "Whether the endpoint is accessible via the native ubyon client",
						Validators: []validator.String{
							stringvalidator.OneOf(
								"ENABLED",
								"DISABLED",
							),
						},
					},
					"ssh_proxy": &schema.StringAttribute{
						Optional:    true,
						Description: "Whether the ssh-proxy is enabled",
						Validators: []validator.String{
							stringvalidator.OneOf(
								"ENABLED",
								"DISABLED",
							),
						},
					},
					"bypass_list": &schema.ListAttribute{
						Optional:    true,
						Description: "The bypass list for the ssh endpoint",
						ElementType: types.ListType{ElemType: types.StringType},
					},
				},
			},
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
							Description: "The format of attributes for SshApp-SecretsStore association",
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

func (ar *SshAppResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func convSshAppToAppResourceModel(sshApp *SshAppResourceModel, app *AppResourceModel) {
	app.Id = sshApp.Id
	app.Name = sshApp.Name
	app.Description = sshApp.Description
	app.Category = types.StringValue("INFRASTRUCTURE")
	app.IsAuthnEnabled = types.BoolValue(false)
	app.ManagedBy = types.StringValue("NONE")
	app.ResourceType = sshApp.ResourceType
	app.ServiceType = types.StringValue("NONE")
	app.SubCategory = types.StringValue("MACHINE")
	app.AppType = sshApp.AppType

	ep := &AppEndpointRaw{
		Endpoint: AppEndpoint{
			AccessType: types.StringValue("NATIVE"),
			Addr: &AppEndpointAddr{
				Value: sshApp.Addr,
				//Type_: String{},
			},
			Attributes: &AppEndpointAttributes{
				SSHAttributes: &sshApp.Attributes,
			},
			AppEndpointId:  sshApp.AppEndpointId,
			OnboardingType: types.StringValue("MANUAL"),
			Port: &AppEndpointPort{
				Type_: types.StringValue("INDIVIDUAL"),
				Value: types.StringValue(fmt.Sprintf("%d", ConvTypesInt64(sshApp.Port))),
			},
			Protocol: types.StringValue("SSH"),
			Source:   types.StringValue("MANUAL"),
			//ServiceTemplateId: nil,
		},
		BaSettings: nil,
	}
	if IsIpStr(ConvTypesString(sshApp.Addr)) {
		ep.Endpoint.Addr.Type_ = types.StringValue("IP")
	} else {
		ep.Endpoint.Addr.Type_ = types.StringValue("FQDN")
	}
	app.Endpoints = []*AppEndpointRaw{ep}

	if !IsTypesStringEmpty(sshApp.NetworkId) {
		app.NetworkIds = []types.String{sshApp.NetworkId}
	}
	app.ConnectorIds = sshApp.ConnectorIds
	app.AuthProviderIds = sshApp.AuthProviderIds
	if !IsTypesStringEmpty(sshApp.AppLaunchpadId) {
		app.AppLaunchpadIds = []types.String{sshApp.AppLaunchpadId}
	}
	app.SecretsStores = sshApp.SecretsStores
	app.AppTagIds = sshApp.AppTagIds
}

func convAppToSshAppResourceModel(ctx context.Context,
	app *AppResourceModel, sshApp *SshAppResourceModel) (err error) {

	sshApp.Id = app.Id
	sshApp.Name = app.Name
	sshApp.Description = app.Description
	sshApp.ResourceType = app.ResourceType
	sshApp.AppType = app.AppType

	if len(app.Endpoints) > 0 && app.Endpoints[0] != nil {
		ep := app.Endpoints[0]
		if ep.Endpoint.Addr != nil {
			sshApp.Addr = ep.Endpoint.Addr.Value
		}
		if ep.Endpoint.Port != nil {
			var portInt64 int64
			portInt64, err = strconv.ParseInt(ConvTypesString(ep.Endpoint.Port.Value), 10, 64)
			if err == nil {
				sshApp.Port = types.Int64Value(portInt64)
			} else {
				tflog.Trace(ctx, fmt.Sprintf("err %v converting %s",
					err, ConvTypesString(ep.Endpoint.Port.Value)))
			}
		}
		if ep.Endpoint.Attributes != nil {
			sshApp.Attributes = *ep.Endpoint.Attributes.SSHAttributes
		}
		sshApp.AppEndpointId = ep.Endpoint.AppEndpointId
	}
	if len(app.NetworkIds) > 0 {
		sshApp.NetworkId = app.NetworkIds[0]
	}
	sshApp.ConnectorIds = app.ConnectorIds
	sshApp.AuthProviderIds = app.AuthProviderIds
	if len(app.AppLaunchpadIds) > 0 {
		sshApp.AppLaunchpadId = app.AppLaunchpadIds[0]
	}
	sshApp.SecretsStores = app.SecretsStores
	sshApp.AppTagIds = app.AppTagIds
	return
}

func (ar *SshAppResource) Create(ctx context.Context,
	req resource.CreateRequest, resp *resource.CreateResponse) {

	var data SshAppResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	var appData AppResourceModel
	convSshAppToAppResourceModel(&data, &appData)
	if !appCreateHelper(ctx, req, resp, &appData, ar.appsApiSvc) {
		return
	}

	convAppToSshAppResourceModel(ctx, &appData, &data)

	// Write logs using the tflog package
	// Documentation: https://terraform.io/plugin/log
	tflog.Trace(ctx, "created a ssh app resource")

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (ar *SshAppResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var curr, data SshAppResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &curr)...)

	if resp.Diagnostics.HasError() {
		return
	}

	//resp.Diagnostics.AddWarning("curr ssh data", spewCfg.Sdump(curr))

	appId := ConvTypesString(curr.Id)
	if len(appId) <= 0 {
		resp.Diagnostics.AddError("SshApp id nil", fmt.Sprintf("%v", curr))
		return
	}

	var currAppData, appData AppResourceModel
	appData.Id = curr.Id

	convSshAppToAppResourceModel(&curr, &currAppData)
	if !appReadHelper(ctx, req, resp, appId, &currAppData, &appData, ar.appsApiSvc) {
		return
	}
	convAppToSshAppResourceModel(ctx, &appData, &data)

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (ar *SshAppResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var curr, data SshAppResourceModel

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
	convSshAppToAppResourceModel(&data, &planApp)
	convSshAppToAppResourceModel(&curr, &currApp)
	if !appUpdateHelper(ctx, req, resp, &currApp, &planApp, ar.appsApiSvc) {
		return
	}
	convAppToSshAppResourceModel(ctx, &planApp, &data)

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (ar *SshAppResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data SshAppResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	appId := ConvTypesString(data.Id)
	if len(appId) <= 0 {
		resp.Diagnostics.AddError("Ssh App id nil", fmt.Sprintf("%v", data))
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

func (ar *SshAppResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
