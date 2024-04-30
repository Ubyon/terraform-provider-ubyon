/*
 *  Copyright © 2021-2024 All rights reserved
 *  Maintainer: Ubyon
 *  Contributors: Laxminarayana Tumuluru
 */

package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"

	"github.com/davecgh/go-spew/spew"

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

var spewCfg = spew.ConfigState{Indent: "\t", MaxDepth: 8, DisableMethods: true}

// Ensure provider defined types fully satisfy framework interfaces.
var _ resource.Resource = &AppResource{}
var _ resource.ResourceWithImportState = &AppResource{}

func NewAppResource() resource.Resource {
	return &AppResource{}
}

// AppResource defines the resource implementation.
type AppResource struct {
	appsApiSvc *corecfgclient.AppsApiService
}

// Key represents the format of credential key attributes for App-SecretsStore association
type Key struct {
	Name  types.String `tfsdk:"name" `
	Value types.String `tfsdk:"value" `
}

// ApiKeyAttributes represents the format of credential apikey attributes for App-SecretsStore association
type ApiKeyAttributes struct {
	Keys []Key `tfsdk:"keys" `
}

// JwtAttributes represents the format of credential jwtkey attributes for App-SecretsStore association
type JwtAttributes struct {
	Keys []Key `tfsdk:"keys" `
}

// AppSecretsStoreAttributes represents the format of attributes for App-SecretsStore association
type UserPswdAttributes struct {
	User Key `tfsdk:"user" `
	Pswd Key `tfsdk:"pswd" `
}

// AppSecretsStoreCertAttributes represents the format of credential certkey attributes for App-SecretsStore association
type AppSecretsStoreCertAttributes struct {
	PrivateKeyPath types.String `tfsdk:"private_key_path"  `
	PublicKeyPath  types.String `tfsdk:"public_key_path"  `
	CaCertPath     types.String `tfsdk:"ca_cert_path"  `
}

// AppSecretsStoreAttributes represents the format of attributes for App-SecretsStore association
type AppSecretsStoreAttributes struct {
	// The credentials of the app-secretsstore association JWT CredentialJwt APIKEY CredentialApiKey USERPSWD CredentialUserPswd CERT CredentialCert
	CredentialType types.String `tfsdk:"credential_type"`
	// The scope of secret store usage by the principals USER SSAPrincipalUser WORKLOAD SSAPrincipalWorkload USER_WORKLOAD SSAPrincipalUserWorkload
	PrincipalScope  types.String                   `tfsdk:"principal_scope"`
	ApiKeyAttribs   *ApiKeyAttributes              `tfsdk:"api_key_attributes"`
	JwtAttribs      *JwtAttributes                 `tfsdk:"jwt_attributes"`
	UserPswdAttribs *UserPswdAttributes            `tfsdk:"user_pswd_attributes"`
	CertAttribs     *AppSecretsStoreCertAttributes `tfsdk:"app_secrets_store_cert_attributes"`
}

type AppSecretsStore struct {
	Attributes *AppSecretsStoreAttributes `tfsdk:"attributes"`
	// The Id of the app to which the secretsstore is associated
	SecretsStoreId types.String `tfsdk:"secrets_store_id"`
}

type AppRoleAttributes struct {
	DbUsers []types.String `tfsdk:"db_users"`
}

// AppRole represents the response format of a app role association
type AppRole struct {
	Attributes *AppRoleAttributes `tfsdk:"attributes"`
	// The Id of the role to which the app is associated
	RoleId types.String `tfsdk:"role_id"`
}

// AppEndpointSSHAttributes represents the request format of Attributes of an AppEndpoint
type AppEndpointSSHAttributes struct {
	UbClient   types.String   `tfsdk:"ub_client"  validate:"omitempty,oneof=ENABLED DISABLED" default:"DISABLED"`
	SshProxy   types.String   `tfsdk:"ssh_proxy"  validate:"omitempty,oneof=ENABLED DISABLED" default:"DISABLED"`
	BypassList []types.String `tfsdk:"bypass_list"  validate:"omitempty,dive,custom_bypass_list"`
}

// AppEndpointK8SAttributes represents the request format of Attributes of an AppEndpoint
type AppEndpointK8SAttributes struct {
	// Whether the endpoint is accessible via the native ubyon client
	K8SUbClient types.String `tfsdk:"k8s_ub_client" db:"k8s_ub_client" validate:"omitempty,oneof=ENABLED DISABLED" default:"ENABLED"`
	// Authentication type
	K8SAuthenticationType types.String `tfsdk:"k8s_authentication_type" db:"k8s_authentication_type" validate:"omitempty,oneof=SSO SERVICEACCOUNT" default:"SSO"`
	// K8S access token to access the cluster
	K8SAccessToken types.String `tfsdk:"k8s_access_token" db:"k8s_access_token" `
	// User identity to authorise access the cluster
	K8SUserIdentity types.String `tfsdk:"k8s_user_identity" db:"k8s_user_identity" validate:"omitempty,oneof=ENABLED DISABLED" default:"DISABLED"`
}

// AppEndpointRDPAttributes represents the request format of Attributes of an AppEndpoint
type AppEndpointRDPAttributes struct {
	UbClient types.String `tfsdk:"ub_client"  validate:"omitempty,oneof=ENABLED DISABLED" default:"ENABLED"`
}

// AppEndpointVNCAttributes represents the request format of Attributes of an AppEndpoint
type AppEndpointVNCAttributes struct {
	UbClient types.String `tfsdk:"ub_client"  validate:"omitempty,oneof=ENABLED DISABLED" default:"ENABLED"`
}

// AppEndpointIdpGroupAttributes represents the request format of Attributes of an AppEndpoint
type AppEndpointIdpGroupAttributes struct {
	GroupId   types.String `tfsdk:"group_id"  `
	GroupName types.String `tfsdk:"group_name"  `
}

// AppEndpointDbTlsConfig represents the request format of tls configuration of an endpoint
type AppEndpointDbTlsConfig struct {
	CertId types.String `tfsdk:"cert_id" `
	DbCA   types.String `tfsdk:"db_ca"  validate:"omitempty,custom_ca_x509=validity;isca"`
}

// AppEndpointDbAttributesDbConfig represents the request format of database configuration for postgres
type AppEndpointDbAttributesDbConfig struct {
	TlsConfig     AppEndpointDbTlsConfig        `tfsdk:"tls_config"  `
	TlsCfgOptions AppEndpointDbTlsConfigOptions `tfsdk:"tls_cfg_options"  `
}

// AppEndpointDefaultDbAttributes represents the request format of DB Attributes of an AppEndpoint
type AppEndpointDefaultDbAttributes struct {
	UbClient types.String                     `tfsdk:"ub_client"  validate:"omitempty,oneof=ENABLED DISABLED" default:"ENABLED"`
	DbProxy  types.String                     `tfsdk:"db_proxy"  validate:"omitempty,oneof=ENABLED DISABLED" default:"ENABLED"`
	DbConfig *AppEndpointDbAttributesDbConfig `tfsdk:"db_config" `
	Region   types.String                     `tfsdk:"region"  `
	StartUri types.String                     `tfsdk:"start_uri"  validate:"omitempty,uri"`
}

// SecretsStoreCredX509Cert represents the Secrets Store Credential of type Certificate
type SecretsStoreCredX509Cert struct {
	PublicKeyPath  types.String `tfsdk:"public_key_path"`
	SecretsStoreId types.String `tfsdk:"secrets_store_id"`
}

type SecretsStoreCredX509Pair struct {
	CaCertPath     types.String `tfsdk:"ca_cert_path,omitempty"`
	PrivateKeyPath types.String `tfsdk:"private_key_path"`
	PublicKeyPath  types.String `tfsdk:"public_key_path"`
	SecretsStoreId types.String `tfsdk:"secrets_store_id"`
}

type AppEndpointDbTlsCfgLocSecretsStore struct {
	ProxyServerCertPath *SecretsStoreCredX509Pair `tfsdk:"proxy_server_cert_path"`
	DbServerCaPath      *SecretsStoreCredX509Cert `tfsdk:"db_server_ca_path"`
}

// AppEndpointDbTlsConfigOptions represents the tls config for database proxy
type AppEndpointDbTlsConfigOptions struct {
	// NONE AppEndpointDbTlsCfgLocTypeNone DIRECT AppEndpointDbTlsCfgLocTypeDirect SECRETS_STORE AppEndpointDbTlsCfgLocTypeSecretsStore
	CfgLocType   types.String                        `tfsdk:"cfg_loc_type"`
	SecretsStore *AppEndpointDbTlsCfgLocSecretsStore `tfsdk:"secrets_store"`
}

type AppEndpointDefaultAttributes struct {
	StartUri types.String `tfsdk:"start_uri"`
}

type AppEndpointAttributes struct {
	SSHAttributes      *AppEndpointSSHAttributes       `tfsdk:"ssh_attributes"`
	K8SAttributes      *AppEndpointK8SAttributes       `tfsdk:"k8s_attributes"`
	RDPAttributes      *AppEndpointRDPAttributes       `tfsdk:"rdp_attributes"`
	VNCAttributes      *AppEndpointVNCAttributes       `tfsdk:"vnc_attributes"`
	IdpGroupAttributes *AppEndpointIdpGroupAttributes  `tfsdk:"idp_group_attributes"`
	DbAttributes       *AppEndpointDefaultDbAttributes `tfsdk:"db_attributes"`
	DefaultAttributes  *AppEndpointDefaultAttributes   `tfsdk:"default_attributes"`
}

// BAHttpAttributes represents the http attributes required for browser access
type BaHttpAttributes struct {
	Headers map[types.String][]types.String `tfsdk:"headers"`
	// The Uri to redirect the users after entering the application. Defaults to \"/\"
	StartUri types.String `tfsdk:"start_uri"`
}

// BAHttpsAttributes represents the https attributes required for browser access
type BaHttpsAttributes struct {
	Headers map[types.String][]types.String `tfsdk:"headers"`
	// The Uri to redirect the users after entering the application. Defaults to \"/\"
	StartUri types.String `tfsdk:"start_uri"`
}

// BASshAttributes represents the ssh attributes required for browser access
type BaSshAttributes struct {
	// Maximum number of concurrent SSH connections
	MaxConnections types.Int64 `tfsdk:"max_connections"`
	// The Uri to redirect the users after entering the application. Defaults to \"/ssh\"
	StartUri types.String `tfsdk:"start_uri"`
}

// BAUrlAliasSettings represents the settings required for configure URL alias
type BaUrlAliasSettings struct {
	// Id of the certificate which matches with the CNAME domain
	CertId types.String `tfsdk:"cert_id"`
	// CNAME associated with the domain
	Cname types.String `tfsdk:"cname"`
}

// BrowserAccessSettings represent the response format of browser access settings for an appendpoint
type BrowserAccessSettings struct {
	// The Id of the browser access settings
	//Id types.String `tfsdk:"id" `
	// The Id of the appendpoint
	AppEndpointId types.String `tfsdk:"app_endpoint_id" `
	// The port on which the server is listening on
	Port types.Int64 `tfsdk:"port" `
	// Enable/Disable URL alias for the application
	UrlAlias types.Bool `tfsdk:"url_alias" `
	// Hosting type for the application settings (UBYON|ENTERPRISE)
	HostingType types.String `tfsdk:"hosting_type" `
	// The resource type of the app (UBYON/ENTERPRISE)
	ResourceType types.String `tfsdk:"resource_type" `
	// The settings to enable URL alias for the application
	UrlAliasSettings *BaUrlAliasSettings `tfsdk:"url_alias_settings" `

	BaHttpAttribs  *BaHttpAttributes  `tfsdk:"http_attributes"`
	BaHttpsAttribs *BaHttpsAttributes `tfsdk:"https_attributes"`
	//BaSshAttribs   *BaSshAttributes   `tfsdk:"ssh_attributes"`
}

// AppEndpointAddr represents the address in either IPAddress or FQDN format
type AppEndpointAddr struct {
	Type_ types.String `tfsdk:"type"`
	Value types.String `tfsdk:"value"`
}

// AppEndpointPort represents the layer4 /layer7  protocol port numbers in ranges or individual lists
type AppEndpointPort struct {
	Type_ types.String `tfsdk:"type"`
	Value types.String `tfsdk:"value"`
}

type AppEndpoint struct {
	// The accesstype of an appendpoint NATIVE AppEndpointAccessTypeNative BROWSER AppEndpointAccessTypeBrowser
	AccessType types.String           `tfsdk:"access_type"`
	Addr       *AppEndpointAddr       `tfsdk:"addr"`
	Attributes *AppEndpointAttributes `tfsdk:"attributes"`
	// The Id of the app endpoint
	AppEndpointId types.String `tfsdk:"app_endpoint_id"`
	// The onboarding type for the application MANUAL AppEndpointOnboardingTypeManual DISCOVERY AppEndpointOnboardingTypeDiscovery
	OnboardingType types.String     `tfsdk:"onboarding_type"`
	Port           *AppEndpointPort `tfsdk:"port"`
	// The layer4 / layer7 protocol of the app endpoint port HTTPS AppEndpointProtocolHTTPS HTTP AppEndpointProtocolHTTP SSH AppEndpointProtocolSSH K8S AppEndpointProtocolK8S TCP AppEndpointProtocolTcp UDP AppEndpointProtocolUdp RDP AppEndpointProtocolRDP VNC AppEndpointProtocolVNC S3 AppEndpointProtocolS3 MYSQL AppEndpointProtocolMySQL POSTGRES AppEndpointProtocolPostgres AURORA_MYSQL AppEndpointProtocolAuroraMySQL AURORA_POSTGRES AppEndpointProtocolAuroraPostgres SQLSERVER AppEndpointProtocolSqlServer MONGODB AppEndpointProtocolMongodb DYNAMODB AppEndpointProtocolDynamodb SNOWFLAKE AppEndpointProtocolSnowflake DATABRICKS AppEndpointProtocolDatabricks
	Protocol types.String `tfsdk:"protocol"`
	// The service template used if any for the application
	ServiceTemplateId types.String `tfsdk:"service_template_id"`
	// The source of an app endpoint MANUAL AppEndpointSourceManual DISCOVERED AppEndpointSourceeDiscovered
	Source types.String `tfsdk:"source"`
}

type AppEndpointRaw struct {
	Endpoint   AppEndpoint            `tfsdk:"endpoint"`
	BaSettings *BrowserAccessSettings `tfsdk:"browser_access_settings"`
}

// AppResourceModel describes the resource data model.
type AppResourceModel struct {

	// The Id of the app
	Id types.String `tfsdk:"id"`
	// The name of the app
	Name types.String `tfsdk:"name"`
	// The description for the app
	Description types.String `tfsdk:"description"`
	// The ID of the asset the app was created from
	AssetId types.String `tfsdk:"asset_id"`
	//Attributes     *IsAppAttributes   `tfsdk:"attributes"`
	//Authentication *AppAuthentication `tfsdk:"authentication"`
	// The category type of the app (NONE/DATASOURCE) NONE AppCategoryNone DATASOURCE AppCategoryDataSource SERVICE AppCategoryService INFRASTRUCTURE AppCategoryInfrastructure SERVICEPROVIDER AppCategoryServiceProvider
	Category types.String `tfsdk:"category"`
	// The app authentication is enabled or not (True/False)
	IsAuthnEnabled types.Bool `tfsdk:"is_authn_enabled"`
	// The manager of the cloud resource NONE ManagedByNone AWS ManagedByAws AZURE ManagedByAzure GCP ManagedByGcp SNOWFLAKE ManagedBySnowflake DATABRICKS ManagedByDatabricks
	ManagedBy types.String `tfsdk:"managed_by"`

	// The resource the AuthProvider manages (UBYON/ENTERPRISE) UBYON ResourceTypeUbyon ENTERPRISE ResourceTypeEnterprise CLOUD ResourceTypeCloud
	ResourceType types.String `tfsdk:"resource_type"`
	// The service provider ID that the app is associated to
	ServiceProviderId types.String `tfsdk:"service_provider_id"`
	// The service type of the app NONE ServiceTypeNone IAMROLE ServiceTypeIamRole IDPGROUP ServiceTypeIdpGroup RESOURCEOWNER ServiceTypeResourceOwner MESHAPP ServiceTypeMeshApp ONCALL ServiceTypeOnCall RDS ServiceTypeRDS EKS ServiceTypeEKS SSM ServiceTypeSSM S3 ServiceTypeS3 SAAS ServiceTypeSaas BLOB ServiceTypeBlob
	ServiceType types.String `tfsdk:"service_type"`
	// The subcategory of the app NONE AppSubCategoryNone MACHINE AppSubCategoryMachine DESKTOP AppSubCategoryDesktop CLUSTER AppSubCategoryCluster DATASOURCE AppSubCategoryDataSource WEB AppSubCategoryWeb AWS AppSubCategoryAws GCP AppSubCategoryGcp AZURE AppSubCategoryAzure OCI AppSubCategoryOci OKTA AppSubCategoryOkta GOOGLE AppSubCategoryGoogle PING AppSubCategoryPing UBYON AppSubCategoryUbyon IBM AppSubCategoryIbm PAGERDUTY AppSubCategoryPagerDuty OPSGENIE AppSubCategoryOpsGenie
	SubCategory types.String `tfsdk:"sub_category"`
	// The Type of the app (PUBLIC|PRIVATE|SHORTCUT) PUBLIC AppPublic PRIVATE AppPrivate SHORTCUT AppShortcut
	AppType types.String `tfsdk:"app_type"`

	Endpoints       []*AppEndpointRaw  `tfsdk:"endpoints"`
	NetworkIds      []types.String     `tfsdk:"network_ids"`
	ConnectorIds    []types.String     `tfsdk:"connector_ids"`
	AuthProviderIds []types.String     `tfsdk:"auth_provider_ids"`
	AppLaunchpadIds []types.String     `tfsdk:"app_launchpad_ids"`
	SecretsStores   []*AppSecretsStore `tfsdk:"secrets_stores"`
	Roles           []*AppRole         `tfsdk:"roles"`
	AppTagIds       []types.String     `tfsdk:"app_tag_ids"`
}

func (ar *AppResource) Metadata(ctx context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_app"
}

func (ar *AppResource) Schema(ctx context.Context, req resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		MarkdownDescription: "Resource schema for App",
		Attributes: map[string]schema.Attribute{
			"asset_id": &schema.StringAttribute{
				Optional:    true,
				Description: "The ID of the asset the app was created from",
				Default:     stringdefault.StaticString(""),
				Computed:    true,
			},
			"category": &schema.StringAttribute{
				Optional:    true,
				Description: "The category type of the app",
				Validators: []validator.String{
					stringvalidator.OneOf(
						"NONE",
						"DATASOURCE",
						"SERVICE",
						"INFRASTRUCTURE",
						"SERVICEPROVIDER",
					),
				},
			},
			"description": &schema.StringAttribute{
				Optional:    true,
				Description: "The description for the app",
				Default:     stringdefault.StaticString(""),
				Computed:    true,
			},
			"id": &schema.StringAttribute{
				Required:    false,
				Computed:    true,
				Optional:    false,
				Description: "The Id of the app",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
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
			"name": &schema.StringAttribute{
				Required:    true,
				Optional:    false,
				Description: "The name of the app",
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
			"service_provider_id": &schema.StringAttribute{
				Optional:    true,
				Description: "The service provider ID that the app is associated to",
				Default:     stringdefault.StaticString(""),
				Computed:    true,
			},
			"service_type": &schema.StringAttribute{
				Optional:    true,
				Description: "The service type of the app",
				Validators: []validator.String{
					stringvalidator.OneOf(
						"NONE",
						"IAMROLE",
						"IDPGROUP",
						"RESOURCEOWNER",
						"MESHAPP",
						"ONCALL",
						"RDS",
						"EKS",
						"SSM",
						"S3",
						"SAAS",
						"BLOB",
					),
				},
				Default:  stringdefault.StaticString("NONE"),
				Computed: true,
			},
			"sub_category": &schema.StringAttribute{
				Optional:    true,
				Description: "The subcategory of the app",
				Validators: []validator.String{
					stringvalidator.OneOf(
						"NONE",
						"MACHINE",
						"DESKTOP",
						"CLUSTER",
						"DATASOURCE",
						"WEB",
						"AWS",
						"GCP",
						"AZURE",
						"OCI",
						"OKTA",
						"GOOGLE",
						"PING",
						"UBYON",
						"IBM",
						"PAGERDUTY",
						"OPSGENIE",
					),
				},
			},
			"app_type": &schema.StringAttribute{
				Optional:    true,
				Description: "The Type of the app",
				Validators: []validator.String{
					stringvalidator.OneOf(
						"PUBLIC",
						"PRIVATE",
						"SHORTCUT",
					),
				},
			},
			"app_launchpad_ids": &schema.ListAttribute{
				Optional:    true,
				Description: "The Ids of the app launchpads",
				ElementType: types.StringType,
			},
			"endpoints": &schema.ListNestedAttribute{
				Optional:    true,
				Description: "The app endpoint",
				NestedObject: schema.NestedAttributeObject{
					CustomType:    nil,
					Validators:    nil,
					PlanModifiers: nil,
					Attributes: map[string]schema.Attribute{
						"browser_access_settings": &schema.SingleNestedAttribute{
							Optional:    true,
							Description: "The browser access settings for an appendpoint",
							Attributes: map[string]schema.Attribute{
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
						"endpoint": &schema.SingleNestedAttribute{
							Optional:    true,
							Description: "The app endpoint",
							Attributes: map[string]schema.Attribute{
								"access_type": &schema.StringAttribute{
									Optional:    true,
									Description: "The accesstype of an appendpoint",
									Validators: []validator.String{
										stringvalidator.OneOf(
											"NATIVE",
											"BROWSER",
										),
									},
								},
								"addr": &schema.SingleNestedAttribute{
									Optional:    true,
									Description: "The address in either IPAddress or FQDN format",
									Attributes: map[string]schema.Attribute{
										"type": &schema.StringAttribute{
											Optional:    true,
											Description: "The type of the address",
											Validators: []validator.String{
												stringvalidator.OneOf(
													"IP",
													"FQDN",
												),
											},
										},
										"value": &schema.StringAttribute{
											Optional:    true,
											Description: "The value of the address",
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
								"onboarding_type": &schema.StringAttribute{
									Optional:    true,
									Description: "The onboarding type for the application",
									Validators: []validator.String{
										stringvalidator.OneOf(
											"MANUAL",
											"DISCOVERY",
										),
									},
									Default:  stringdefault.StaticString("MANUAL"),
									Computed: true,
								},
								"port": &schema.SingleNestedAttribute{
									Optional:    true,
									Description: "The layer4 /layer7  protocol port numbers in ranges or individual lists",
									Attributes: map[string]schema.Attribute{
										"type": &schema.StringAttribute{
											Optional:    true,
											Description: "The type of the port",
											Validators: []validator.String{
												stringvalidator.OneOf(
													"INDIVIDUAL",
													"RANGE",
												),
											},
										},
										"value": &schema.StringAttribute{
											Optional:    true,
											Description: "The value of the port",
										},
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
											"SSH",
											"K8S",
											"TCP",
											"UDP",
											"RDP",
											"VNC",
											"S3",
											"MYSQL",
											"POSTGRES",
											"AURORA_MYSQL",
											"AURORA_POSTGRES",
											"SQLSERVER",
											"MONGODB",
											"DYNAMODB",
											"SNOWFLAKE",
											"DATABRICKS",
										),
									},
								},
								"attributes": &schema.SingleNestedAttribute{
									Optional:    true,
									Description: "The app endpoint attributes",
									Attributes: map[string]schema.Attribute{
										"ssh_attributes": &schema.SingleNestedAttribute{
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
										"k8s_attributes": &schema.SingleNestedAttribute{
											Optional:    true,
											Description: "The request format of k8s Attributes of an AppEndpoint",
											Attributes: map[string]schema.Attribute{
												"k8s_ub_client": &schema.StringAttribute{
													Optional:    true,
													Description: "Whether the endpoint is accessible via the native ubyon client",
													Validators: []validator.String{
														stringvalidator.OneOf(
															"ENABLED",
															"DISABLED",
														),
													},
												},
												"k8s_authentication_type": &schema.StringAttribute{
													Optional:    true,
													Description: "Authentication type",
													Validators: []validator.String{
														stringvalidator.OneOf(
															"SSO",
															"SERVICEACCOUNT",
														),
													},
												},
												"k8s_access_token": &schema.StringAttribute{
													Optional:    true,
													Description: "K8S access token to access the cluster",
												},
												"k8s_user_identity": &schema.StringAttribute{
													Optional:    true,
													Description: "User identity to authorise access the cluster",
													Validators: []validator.String{
														stringvalidator.OneOf(
															"ENABLED",
															"DISABLED",
														),
													},
												},
											},
										},
										"rdp_attributes": &schema.SingleNestedAttribute{
											Optional:    true,
											Description: "The request format of rdp Attributes of an AppEndpoint",
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
											},
										},
										"vnc_attributes": &schema.SingleNestedAttribute{
											Optional:    true,
											Description: "The request format of vnc Attributes of an AppEndpoint",
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
											},
										},
										"idp_group_attributes": &schema.SingleNestedAttribute{
											Optional:    true,
											Description: "The request format of idpGroup Attributes of an AppEndpoint",
											Attributes: map[string]schema.Attribute{
												"group_id": &schema.StringAttribute{
													Optional:    true,
													Description: "The group Id",
												},
												"group_name": &schema.StringAttribute{
													Optional:    true,
													Description: "The group name",
												},
											},
										},
										"db_attributes": &schema.SingleNestedAttribute{
											Optional:    true,
											Description: "The request format of db Attributes of an AppEndpoint",
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
												"db_proxy": &schema.StringAttribute{
													Optional:    true,
													Description: "Whether the db-proxy is enabled",
													Validators: []validator.String{
														stringvalidator.OneOf(
															"ENABLED",
															"DISABLED",
														),
													},
												},
												"db_config": &schema.SingleNestedAttribute{
													Optional:    true,
													Description: "The database configuration for the app",
													Attributes: map[string]schema.Attribute{
														"tls_config": &schema.SingleNestedAttribute{
															Optional:    true,
															Description: "The tls configuration of an endpoint",
															Attributes: map[string]schema.Attribute{
																"cert_id": &schema.StringAttribute{
																	Optional:    true,
																	Description: "The Id of the certificate",
																},
																"db_ca": &schema.StringAttribute{
																	Optional:    true,
																	Description: "The CA of the database",
																},
															},
														},
														"tls_cfg_options": &schema.SingleNestedAttribute{
															Optional:    true,
															Description: "The tls config for database proxy",
															Attributes: map[string]schema.Attribute{
																"cfg_loc_type": &schema.StringAttribute{
																	Optional:    true,
																	Description: "The location type of the tls config",
																	Validators: []validator.String{
																		stringvalidator.OneOf(
																			"NONE",
																			"DIRECT",
																			"SECRETS_STORE",
																		),
																	},
																},
																"secrets_store": &schema.SingleNestedAttribute{
																	Optional:    true,
																	Description: "The secrets store for the tls config",
																	Attributes: map[string]schema.Attribute{
																		"proxy_server_cert_path": &schema.SingleNestedAttribute{
																			Optional:    true,
																			Description: "The proxy server cert path",
																			Attributes: map[string]schema.Attribute{
																				"ca_cert_path": &schema.StringAttribute{
																					Optional:    true,
																					Description: "The CA cert path",
																				},
																				"private_key_path": &schema.StringAttribute{
																					Optional:    true,
																					Description: "The private key path",
																				},
																			},
																		},
																		"db_server_ca_path": &schema.SingleNestedAttribute{
																			Optional:    true,
																			Description: "The db server CA path",
																			Attributes: map[string]schema.Attribute{
																				"public_key_path": &schema.StringAttribute{
																					Optional:    true,
																					Description: "The public key path",
																				},
																				"secrets_store_id": &schema.StringAttribute{
																					Optional:    true,
																					Description: "The secrets store Id",
																				},
																			},
																		},
																	},
																},
															},
														},
													},
												},
											},
										},
										"default_attributes": &schema.SingleNestedAttribute{
											Optional:    true,
											Description: "The default attributes of an AppEndpoint",
											Attributes: map[string]schema.Attribute{
												"start_uri": &schema.StringAttribute{
													Optional:    true,
													Description: "The Uri to redirect the users after entering the application",
												},
											},
										},
									},
								},
								"service_template_id": &schema.StringAttribute{
									Optional:    true,
									Description: "The service template used if any for the application",
								},
								"source": &schema.StringAttribute{
									Optional:    true,
									Description: "The source of an app endpoint",
								},
							},
						},
					},
				},
			},
			"network_ids": &schema.ListAttribute{
				Optional:    true,
				Description: "The Ids of the app networks",
				ElementType: types.StringType,
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
							Description: "The format of attributes for App-SecretsStore association",
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
			"roles": &schema.ListNestedAttribute{
				Optional:    true,
				Description: "The app roles",
				NestedObject: schema.NestedAttributeObject{
					CustomType:    nil,
					Validators:    nil,
					PlanModifiers: nil,
					Attributes: map[string]schema.Attribute{
						"role_id": &schema.StringAttribute{
							Required:    true,
							Optional:    false,
							Description: "The Id of the role to which the app is associated",
						},
						"attributes": &schema.SingleNestedAttribute{
							Optional:    true,
							Description: "The format of attributes for App-Role association",
							Attributes: map[string]schema.Attribute{
								"db_users": &schema.ListAttribute{
									Optional:    true,
									Description: "DB users",
									ElementType: types.StringType,
								},
							},
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

func (ar *AppResource) Configure(ctx context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func createBackendAppObj(
	data *AppResourceModel) (compReqs []corecfgclient.CompositeAppResourceRaw) {

	newApp := &corecfgclient.NewApp{
		ApprovalConfig:    nil,
		AssetId:           ConvTypesString(data.AssetId),
		Attributes:        nil,
		Authentication:    nil,
		Category:          ConvTypesString(data.Category),
		Description:       ConvTypesString(data.Description),
		IsAuthnEnabled:    ConvTypesBool(data.IsAuthnEnabled),
		ManagedBy:         ConvTypesString(data.ManagedBy),
		Name:              ConvTypesString(data.Name),
		ResourceType:      ConvTypesString(data.ResourceType),
		ServiceProviderId: ConvTypesString(data.ServiceProviderId),
		ServiceType:       ConvTypesString(data.ServiceType),
		SubCategory:       ConvTypesString(data.SubCategory),
		Type_:             ConvTypesString(data.AppType),
	}

	compRs := corecfgclient.CompositeAppResourceRaw{
		Body:        newApp,
		Method:      http.MethodPost,
		ReferenceId: "app-raw-post",
		Type_:       "APP",
	}
	compReqs = []corecfgclient.CompositeAppResourceRaw{compRs}

	if len(data.AppLaunchpadIds) > 0 {
		strArr := ConvTypesArrayString(data.AppLaunchpadIds)
		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        strArr,
			Method:      http.MethodPost,
			ReferenceId: "app_launchpadId_POST",
			Type_:       "APPLAUNCHPAD",
		}
		compReqs = append(compReqs, compRs)
	}

	if len(data.Endpoints) > 0 {
		var newAppEps []*corecfgclient.NewAppEndpointRaw

		for _, ep := range data.Endpoints {
			if ep == nil {
				continue
			}

			newAppEp := &corecfgclient.NewAppEndpointRaw{
				AccessType:            ConvTypesString(ep.Endpoint.AccessType),
				Addr:                  nil,
				Attributes:            nil,
				OnboardingType:        ConvTypesString(ep.Endpoint.OnboardingType),
				BrowserAccessSettings: nil,
				Port:                  nil,
				Protocol:              ConvTypesString(ep.Endpoint.Protocol),
				ServiceTemplateId:     ConvTypesString(ep.Endpoint.ServiceTemplateId),
				Source:                ConvTypesString(ep.Endpoint.Source),
			}
			if ep.Endpoint.Addr != nil {
				newAppEp.Addr = &corecfgclient.AppEndpointAddr{
					Type_: ConvTypesString(ep.Endpoint.Addr.Type_),
					Value: ConvTypesString(ep.Endpoint.Addr.Value),
				}
			}
			if ep.Endpoint.Port != nil {
				newAppEp.Port = &corecfgclient.AppEndpointPort{
					Type_: ConvTypesString(ep.Endpoint.Port.Type_),
					Value: ConvTypesString(ep.Endpoint.Port.Value),
				}
			}

			if ep.Endpoint.Attributes != nil {
				switch {
				case ep.Endpoint.Attributes.SSHAttributes != nil:
					newAppEp.Attributes = &corecfgclient.AppEndpointSshAttributes{
						UbClient:   ConvTypesString(ep.Endpoint.Attributes.SSHAttributes.UbClient),
						SshProxy:   ConvTypesString(ep.Endpoint.Attributes.SSHAttributes.SshProxy),
						BypassList: ConvTypesArrayString(ep.Endpoint.Attributes.SSHAttributes.BypassList),
					}
				case ep.Endpoint.Attributes.K8SAttributes != nil:
					newAppEp.Attributes = &corecfgclient.AppEndpointK8SAttributes{
						K8sUbClient:           ConvTypesString(ep.Endpoint.Attributes.K8SAttributes.K8SUbClient),
						K8sAuthenticationType: ConvTypesString(ep.Endpoint.Attributes.K8SAttributes.K8SAuthenticationType),
						K8sAccessToken:        ConvTypesString(ep.Endpoint.Attributes.K8SAttributes.K8SAccessToken),
						K8sUserIdentity:       ConvTypesString(ep.Endpoint.Attributes.K8SAttributes.K8SUserIdentity),
					}
				case ep.Endpoint.Attributes.RDPAttributes != nil:
					newAppEp.Attributes = &corecfgclient.AppEndpointRdpAttributes{
						UbClient: ConvTypesString(ep.Endpoint.Attributes.RDPAttributes.UbClient),
					}
				case ep.Endpoint.Attributes.VNCAttributes != nil:
					newAppEp.Attributes = &corecfgclient.AppEndpointVncAttributes{
						UbClient: ConvTypesString(ep.Endpoint.Attributes.VNCAttributes.UbClient),
					}
				case ep.Endpoint.Attributes.IdpGroupAttributes != nil:
					newAppEp.Attributes = &corecfgclient.AppEndpointIdpGroupAttributes{
						GroupId:   ConvTypesString(ep.Endpoint.Attributes.IdpGroupAttributes.GroupId),
						GroupName: ConvTypesString(ep.Endpoint.Attributes.IdpGroupAttributes.GroupName),
					}
				case ep.Endpoint.Attributes.DbAttributes != nil:
					switch ConvTypesString(ep.Endpoint.Protocol) {
					case "MYSQL":
						newAppEp.Attributes = &corecfgclient.AppEndpointMySqlAttributes{
							UbClient: ConvTypesString(ep.Endpoint.Attributes.DbAttributes.UbClient),
							DbProxy:  ConvTypesString(ep.Endpoint.Attributes.DbAttributes.DbProxy),
							DbConfig: &corecfgclient.AppEndpointMySqlAttributesDbConfig{
								TlsConfig: &corecfgclient.AppEndpointMySqlTlsConfig{
									CertId: ConvTypesString(ep.Endpoint.Attributes.DbAttributes.DbConfig.TlsConfig.CertId),
									DbCA:   ConvTypesString(ep.Endpoint.Attributes.DbAttributes.DbConfig.TlsConfig.DbCA),
								},
							},
						}
					case "POSTGRES":
						newAppEp.Attributes = &corecfgclient.AppEndpointPostgresAttributes{
							UbClient: ConvTypesString(ep.Endpoint.Attributes.DbAttributes.UbClient),
							DbProxy:  ConvTypesString(ep.Endpoint.Attributes.DbAttributes.DbProxy),
							DbConfig: &corecfgclient.AppEndpointPostgresAttributesDbConfig{
								TlsConfig: &corecfgclient.AppEndpointPostgresTlsConfig{
									CertId: ConvTypesString(ep.Endpoint.Attributes.DbAttributes.DbConfig.TlsConfig.CertId),
									DbCA:   ConvTypesString(ep.Endpoint.Attributes.DbAttributes.DbConfig.TlsConfig.DbCA),
								},
							},
						}
					default:
						newAppEp.Attributes = &corecfgclient.AppEndpointDefaultDbAttributes{
							UbClient: ConvTypesString(ep.Endpoint.Attributes.DbAttributes.UbClient),
							DbProxy:  ConvTypesString(ep.Endpoint.Attributes.DbAttributes.DbProxy),
							Region:   ConvTypesString(ep.Endpoint.Attributes.DbAttributes.Region),
							StartUri: ConvTypesString(ep.Endpoint.Attributes.DbAttributes.StartUri),
							DbConfig: &corecfgclient.AppEndpointPostgresAttributesDbConfig{
								TlsConfig: &corecfgclient.AppEndpointPostgresTlsConfig{
									CertId: ConvTypesString(ep.Endpoint.Attributes.DbAttributes.DbConfig.TlsConfig.CertId),
									DbCA:   ConvTypesString(ep.Endpoint.Attributes.DbAttributes.DbConfig.TlsConfig.DbCA),
								},
							},
						}
					}
				case ep.Endpoint.Attributes.DefaultAttributes != nil && !IsTypesStringEmpty(ep.Endpoint.Attributes.DefaultAttributes.StartUri):
					newAppEp.Attributes = &corecfgclient.AppEndpointDefaultAttributes{
						StartUri: ConvTypesString(ep.Endpoint.Attributes.DefaultAttributes.StartUri),
					}
				}
			}
			if ep.BaSettings != nil {
				newAppEp.BrowserAccessSettings = &corecfgclient.NewBrowserAccessSettings{
					UrlAlias:         ConvTypesBool(ep.BaSettings.UrlAlias),
					HostingType:      ConvTypesString(ep.BaSettings.HostingType),
					ResourceType:     ConvTypesString(ep.BaSettings.ResourceType),
					Attributes:       nil,
					UrlAliasSettings: nil,
				}

				if ep.BaSettings.UrlAliasSettings != nil {
					newAppEp.BrowserAccessSettings.UrlAliasSettings = &corecfgclient.BaUrlAliasSettings{
						CertId: ConvTypesString(ep.BaSettings.UrlAliasSettings.CertId),
						Cname:  ConvTypesString(ep.BaSettings.UrlAliasSettings.Cname),
					}
				}

				if ep.BaSettings.BaHttpAttribs != nil {
					newAppEp.BrowserAccessSettings.Attributes = &corecfgclient.BaHttpAttributes{
						Headers:  ConvTypesMapStringArray(ep.BaSettings.BaHttpAttribs.Headers),
						StartUri: ConvTypesString(ep.BaSettings.BaHttpAttribs.StartUri),
					}
				} else if ep.BaSettings.BaHttpsAttribs != nil {
					newAppEp.BrowserAccessSettings.Attributes = &corecfgclient.BaHttpsAttributes{
						Headers:  ConvTypesMapStringArray(ep.BaSettings.BaHttpsAttribs.Headers),
						StartUri: ConvTypesString(ep.BaSettings.BaHttpsAttribs.StartUri),
					}
				} /*else if ep.BaSettings.BaSshAttribs != nil {
					newAppEp.BrowserAccessSettings.Attributes = &corecfgclient.BaSshAttributes{
						MaxConnections: ConvTypesInt64(ep.BaSettings.BaSshAttribs.MaxConnections),
						StartUri:       ConvTypesString(ep.BaSettings.BaSshAttribs.StartUri),
					}
				}*/
			}
			newAppEps = append(newAppEps, newAppEp)
		}
		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        newAppEps,
			Method:      http.MethodPost,
			ReferenceId: "appendpointpost",
			Type_:       "APPENDPOINT",
		}
		compReqs = append(compReqs, compRs)
	}

	if len(data.Roles) > 0 {
		var appRoles []corecfgclient.NewAppRole
		for _, role := range data.Roles {
			if role == nil {
				continue
			}

			newAppRole := &corecfgclient.NewAppRole{
				Attributes: nil,
				RoleId:     ConvTypesString(role.RoleId),
			}

			if role.Attributes != nil && len(role.Attributes.DbUsers) > 0 {
				newAppRole.Attributes = &corecfgclient.AppRoleAttributes{}
				for _, dbUser := range role.Attributes.DbUsers {
					newAppRole.Attributes.DbUsers = append(newAppRole.Attributes.DbUsers, ConvTypesString(dbUser))
				}
			}

			appRoles = append(appRoles, *newAppRole)
		}

		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        appRoles,
			Method:      http.MethodPost,
			ReferenceId: "app_approles_POST",
			Type_:       "APPROLE",
		}
		compReqs = append(compReqs, compRs)
	}

	if len(data.SecretsStores) > 0 {
		var sss []*corecfgclient.NewAppSecretsStore

		for _, ss := range data.SecretsStores {
			if ss == nil || ss.Attributes == nil {
				continue
			}

			secretStoreId := ConvTypesString(ss.SecretsStoreId)
			newAppSecretStore := &corecfgclient.NewAppSecretsStore{
				Attributes: &corecfgclient.AppSecretsStoreAttributes{
					CredentialType: corecfgclient.CredentialType(ConvTypesString(ss.Attributes.CredentialType)),
					PrincipalScope: ConvTypesString(ss.Attributes.PrincipalScope),
				},
				SecretsStoreId: secretStoreId,
			}

			switch ConvTypesString(ss.Attributes.CredentialType) {
			case "APIKEY":
				if ss.Attributes.ApiKeyAttribs != nil &&
					len(ss.Attributes.ApiKeyAttribs.Keys) > 0 {
					aka := &corecfgclient.ApiKeyAttributes{Keys: make([]corecfgclient.Key, len(ss.Attributes.ApiKeyAttribs.Keys))}
					for i := 0; i < len(ss.Attributes.ApiKeyAttribs.Keys); i++ {
						k1 := &aka.Keys[i]
						k2 := &ss.Attributes.ApiKeyAttribs.Keys[i]

						k1.Name = ConvTypesString(k2.Name)
						k1.Value = ConvTypesString(k2.Value)
					}
					newAppSecretStore.Attributes.Attributes = aka
				}

			case "JWT":
				if ss.Attributes.JwtAttribs != nil &&
					len(ss.Attributes.JwtAttribs.Keys) > 0 {
					jka := &corecfgclient.JwtAttributes{Keys: make([]corecfgclient.Key, len(ss.Attributes.JwtAttribs.Keys))}
					for i := 0; i < len(ss.Attributes.JwtAttribs.Keys); i++ {
						k1 := &jka.Keys[i]
						k2 := &ss.Attributes.JwtAttribs.Keys[i]

						k1.Name = ConvTypesString(k2.Name)
						k1.Value = ConvTypesString(k2.Value)
					}
					newAppSecretStore.Attributes.Attributes = jka
				}

			case "USERPSWD":
				if ss.Attributes.UserPswdAttribs != nil {
					newAppSecretStore.Attributes.Attributes = &corecfgclient.UserPswdAttributes{
						User: &corecfgclient.Key{
							Name:  ConvTypesString(ss.Attributes.UserPswdAttribs.User.Name),
							Value: ConvTypesString(ss.Attributes.UserPswdAttribs.User.Value),
						},
						Pswd: &corecfgclient.Key{
							Name:  ConvTypesString(ss.Attributes.UserPswdAttribs.Pswd.Name),
							Value: ConvTypesString(ss.Attributes.UserPswdAttribs.Pswd.Value),
						},
					}
				}
			case "CERT":
				if ss.Attributes.CertAttribs != nil {
					newAppSecretStore.Attributes.Attributes = &corecfgclient.AppSecretsStoreCertAttributes{
						PrivateKeyPath: ConvTypesString(ss.Attributes.CertAttribs.PrivateKeyPath),
						PublicKeyPath:  ConvTypesString(ss.Attributes.CertAttribs.PublicKeyPath),
						CaCertPath:     ConvTypesString(ss.Attributes.CertAttribs.CaCertPath),
					}
				}
			}

			sss = append(sss, newAppSecretStore)
		}

		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        sss,
			Method:      http.MethodPost,
			ReferenceId: "app_ss_POST",
			Type_:       "APPSECRETSSTORE",
		}
		compReqs = append(compReqs, compRs)
	}

	if len(data.NetworkIds) > 0 {
		strArr := ConvTypesArrayString(data.NetworkIds)
		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        strArr,
			Method:      http.MethodPost,
			ReferenceId: "app-network-POST",
			Type_:       "NETWORK",
		}
		compReqs = append(compReqs, compRs)
	}

	if len(data.ConnectorIds) > 0 {
		strArr := ConvTypesArrayString(data.ConnectorIds)
		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        strArr,
			Method:      http.MethodPost,
			ReferenceId: "app-connectors-POST",
			Type_:       "APPCONNECTOR",
		}
		compReqs = append(compReqs, compRs)
	}

	if len(data.AuthProviderIds) > 0 {
		strArr := ConvTypesArrayString(data.AuthProviderIds)
		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        strArr,
			Method:      http.MethodPost,
			ReferenceId: "app-authprovider-POST",
			Type_:       "AUTHPROVIDER",
		}
		compReqs = append(compReqs, compRs)
	}

	if len(data.AppTagIds) > 0 {
		strArr := ConvTypesArrayString(data.AppTagIds)
		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        strArr,
			Method:      http.MethodPost,
			ReferenceId: "app-tag-POST",
			Type_:       "APPTAG",
		}
		compReqs = append(compReqs, compRs)
	}

	return compReqs
}

func appCreateHelper(ctx context.Context, req resource.CreateRequest,
	resp *resource.CreateResponse, data *AppResourceModel,
	appsApiSvc *corecfgclient.AppsApiService) (success bool) {

	compReqs := createBackendAppObj(data)
	bs, err := json.Marshal(compReqs)
	tflog.Trace(ctx, fmt.Sprintf("app create backend: %s", string(bs)))

	apiResp, httpResp, err := appsApiSvc.CompositeAppCreate(ctx, compReqs)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to create app, got error: %s", err))
		return false
	}

	if httpResp == nil {
		resp.Diagnostics.AddError("unexpected response from API", fmt.Sprintf("%v", httpResp))
		return false
	}
	if httpResp.StatusCode != 200 {
		resp.Diagnostics.AddError("unexpected response from API. Got an unexpected response code %v", fmt.Sprintf("%d", httpResp.StatusCode))
		return false
	}

	resp.Diagnostics.AddWarning("Create resp", spewCfg.Sdump(apiResp))

	if apiResp.Data == nil || apiResp.Data.App == nil {
		resp.Diagnostics.AddError("unexpected response from API. No response body", fmt.Sprintf("%v", apiResp))
		return false
	}
	if len(apiResp.Data.App.Id) <= 0 {
		resp.Diagnostics.AddError("unexpected response from API. No App-Id", fmt.Sprintf("%v", apiResp.Data.App))
		return false
	}

	// For the purposes of this example code, hardcoding a response value to
	// save into the Terraform state.
	data.Id = types.StringValue(apiResp.Data.App.Id)
	for i := 0; i < len(apiResp.Data.AppEndpoints); i++ {
		ae := &apiResp.Data.AppEndpoints[i]
		if i < len(data.Endpoints) {
			ep := data.Endpoints[i]
			if ep != nil {
				ep.Endpoint.AppEndpointId = types.StringValue(ae.Id)
				if ep.BaSettings != nil && ae.BrowserAccessSettings != nil {
					ep.BaSettings.AppEndpointId = types.StringValue(ae.Id)
					ep.BaSettings.UrlAlias = types.BoolValue(ae.BrowserAccessSettings.UrlAlias)
					ep.BaSettings.ResourceType = types.StringValue(ae.BrowserAccessSettings.ResourceType)
				}
			}
		}
	}

	return true
}

func (ar *AppResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var data AppResourceModel

	// Read Terraform plan data into the model
	resp.Diagnostics.Append(req.Plan.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if !appCreateHelper(ctx, req, resp, &data, ar.appsApiSvc) {
		return
	}

	// Write logs using the tflog package
	// Documentation: https://terraform.io/plugin/log
	tflog.Trace(ctx, "created an app resource")

	// Save data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func appReadHelper(ctx context.Context, req resource.ReadRequest,
	resp *resource.ReadResponse, appId string, curr, data *AppResourceModel,
	appsApiSvc *corecfgclient.AppsApiService) (success bool) {

	apiResp, httpResp, err := appsApiSvc.CompositeGetAppById(ctx, appId)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to create app, got error: %s", err))
		return
	}

	if httpResp == nil {
		resp.Diagnostics.AddError("unexpected response from API", fmt.Sprintf("%v", httpResp))
		return
	}
	if httpResp.StatusCode != 200 {
		resp.Diagnostics.AddError("unexpected response from API. Got an unexpected response code %v", fmt.Sprintf("%d", httpResp.StatusCode))
		return
	}

	resp.Diagnostics.AddWarning("Get resp", spewCfg.Sdump(apiResp.Data))

	if apiResp.Data == nil || apiResp.Data.App == nil {
		resp.Diagnostics.AddError("unexpected response from API. No response body", fmt.Sprintf("%v", apiResp))
		return
	}

	car := apiResp.Data
	data.Id = types.StringValue(car.App.Id)
	data.AssetId = types.StringValue(car.App.AssetId)
	data.Category = types.StringValue(car.App.Category)
	data.Description = types.StringValue(car.App.Description)
	data.IsAuthnEnabled = types.BoolValue(car.App.IsAuthnEnabled)
	data.ManagedBy = types.StringValue(car.App.ManagedBy)
	data.Name = types.StringValue(car.App.Name)
	data.ResourceType = types.StringValue(car.App.ResourceType)
	data.ServiceProviderId = types.StringValue(car.App.ServiceProviderId)
	data.ServiceType = types.StringValue(car.App.ServiceType)
	data.SubCategory = types.StringValue(car.App.SubCategory)
	data.AppType = types.StringValue(car.App.Type_)

	if len(car.AppEndpoints) > 0 {
		data.Endpoints = make([]*AppEndpointRaw, len(car.AppEndpoints))
	} else {
		data.Endpoints = nil
	}
	for i := 0; i < len(car.AppEndpoints); i++ {
		ae := &car.AppEndpoints[i]

		dataEp := &AppEndpointRaw{
			Endpoint: AppEndpoint{
				AccessType:        types.StringValue(ae.AccessType),
				Addr:              nil,
				Attributes:        nil,
				AppEndpointId:     types.StringValue(ae.Id),
				OnboardingType:    types.StringValue(ae.OnboardingType),
				Port:              nil,
				Protocol:          types.StringValue(string(ae.Protocol)),
				ServiceTemplateId: types.StringValue(ae.ServiceTemplateId),
				Source:            types.StringValue(ae.Source),
			},
			BaSettings: nil,
		}
		data.Endpoints[i] = dataEp

		if ae.Addr != nil {
			dataEp.Endpoint.Addr = &AppEndpointAddr{
				Type_: types.StringValue(ae.Addr.Type_),
				Value: types.StringValue(ae.Addr.Value),
			}
		}
		if ae.Port != nil {
			dataEp.Endpoint.Port = &AppEndpointPort{
				Type_: types.StringValue(ae.Port.Type_),
				Value: types.StringValue(ae.Port.Value),
			}
		}
		if ae.Attributes != nil {
			dataEp.Endpoint.Attributes = &AppEndpointAttributes{}

			switch ae.Protocol {
			case corecfgclient.AppEndpointProtocolSSH:
				ssha, ok := ae.Attributes.(*corecfgclient.AppEndpointSshAttributes)
				if ok && ssha != nil {
					dataEp.Endpoint.Attributes.SSHAttributes = &AppEndpointSSHAttributes{
						UbClient:   types.StringValue(ssha.UbClient),
						SshProxy:   types.StringValue(ssha.SshProxy),
						BypassList: ConvStringTypesArray(ssha.BypassList),
					}
				}
			case corecfgclient.AppEndpointProtocolK8S:
				k8sa, ok := ae.Attributes.(*corecfgclient.AppEndpointK8SAttributes)
				if ok && k8sa != nil {
					dataEp.Endpoint.Attributes.K8SAttributes = &AppEndpointK8SAttributes{
						K8SUbClient:           types.StringValue(k8sa.K8sUbClient),
						K8SAuthenticationType: types.StringValue(k8sa.K8sAuthenticationType),
						K8SAccessToken:        types.StringValue(k8sa.K8sAccessToken),
						K8SUserIdentity:       types.StringValue(k8sa.K8sUserIdentity),
					}
				}
			case corecfgclient.AppEndpointProtocolRDP:
				rdpa, ok := ae.Attributes.(*corecfgclient.AppEndpointRdpAttributes)
				if ok && rdpa != nil {
					dataEp.Endpoint.Attributes.RDPAttributes = &AppEndpointRDPAttributes{
						UbClient: types.StringValue(rdpa.UbClient),
					}
				}
			case corecfgclient.AppEndpointProtocolVNC:
				vnca, ok := ae.Attributes.(*corecfgclient.AppEndpointVncAttributes)
				if ok && vnca != nil {
					dataEp.Endpoint.Attributes.VNCAttributes = &AppEndpointVNCAttributes{
						UbClient: types.StringValue(vnca.UbClient),
					}
				}
			case corecfgclient.AppEndpointProtocolMySQL:
				mysqla, ok := ae.Attributes.(*corecfgclient.AppEndpointMySqlAttributes)
				if ok && mysqla != nil {
					aedda := &AppEndpointDefaultDbAttributes{
						UbClient: types.StringValue(mysqla.UbClient),
						DbProxy:  types.StringValue(mysqla.DbProxy),
						DbConfig: nil,
					}

					if mysqla.DbConfig != nil {
						aedda.DbConfig = &AppEndpointDbAttributesDbConfig{}

						if mysqla.DbConfig.TlsConfig != nil {
							aedda.DbConfig.TlsConfig.CertId = types.StringValue(mysqla.DbConfig.TlsConfig.CertId)
							aedda.DbConfig.TlsConfig.DbCA = types.StringValue(mysqla.DbConfig.TlsConfig.DbCA)
						}

						if mysqla.DbConfig.TlsCfgOptions != nil {
							aedda.DbConfig.TlsCfgOptions.CfgLocType = types.StringValue(mysqla.DbConfig.TlsCfgOptions.CfgLocType)
							if mysqla.DbConfig.TlsCfgOptions.CfgLocation != nil &&
								mysqla.DbConfig.TlsCfgOptions.CfgLocType == "SECRETS_STORE" {

								cltss, ok := mysqla.DbConfig.TlsCfgOptions.CfgLocation.(*corecfgclient.AppEndpointDbTlsCfgLocSecretsStore)
								if ok && cltss != nil {
									aedda.DbConfig.TlsCfgOptions.SecretsStore = &AppEndpointDbTlsCfgLocSecretsStore{}

									if cltss.DbServerCaPath != nil {
										aedda.DbConfig.TlsCfgOptions.SecretsStore.DbServerCaPath = &SecretsStoreCredX509Cert{
											PublicKeyPath:  types.StringValue(cltss.DbServerCaPath.PublicKeyPath),
											SecretsStoreId: types.StringValue(cltss.DbServerCaPath.SecretsStoreId),
										}
									}
									if cltss.ProxyServerCertPath != nil {
										aedda.DbConfig.TlsCfgOptions.SecretsStore.ProxyServerCertPath = &SecretsStoreCredX509Pair{
											CaCertPath:     types.StringValue(cltss.ProxyServerCertPath.CaCertPath),
											PrivateKeyPath: types.StringValue(cltss.ProxyServerCertPath.PrivateKeyPath),
											PublicKeyPath:  types.StringValue(cltss.ProxyServerCertPath.PublicKeyPath),
											SecretsStoreId: types.StringValue(cltss.ProxyServerCertPath.SecretsStoreId),
										}
									}
								}
							}
						}
					}
					dataEp.Endpoint.Attributes.DbAttributes = aedda
				}

			case corecfgclient.AppEndpointProtocolPostgres:
				pga, ok := ae.Attributes.(*corecfgclient.AppEndpointPostgresAttributes)
				if ok && pga != nil {
					aedda := &AppEndpointDefaultDbAttributes{
						UbClient: types.StringValue(pga.UbClient),
						DbProxy:  types.StringValue(pga.DbProxy),
						DbConfig: nil,
					}

					if pga.DbConfig != nil {
						aedda.DbConfig = &AppEndpointDbAttributesDbConfig{}

						if pga.DbConfig.TlsConfig != nil {
							aedda.DbConfig.TlsConfig.CertId = types.StringValue(pga.DbConfig.TlsConfig.CertId)
							aedda.DbConfig.TlsConfig.DbCA = types.StringValue(pga.DbConfig.TlsConfig.DbCA)
						}

						if pga.DbConfig.TlsCfgOptions != nil {
							aedda.DbConfig.TlsCfgOptions.CfgLocType = types.StringValue(pga.DbConfig.TlsCfgOptions.CfgLocType)
							if pga.DbConfig.TlsCfgOptions.CfgLocation != nil &&
								pga.DbConfig.TlsCfgOptions.CfgLocType == "SECRETS_STORE" {

								cltss, ok := pga.DbConfig.TlsCfgOptions.CfgLocation.(*corecfgclient.AppEndpointDbTlsCfgLocSecretsStore)
								if ok && cltss != nil {
									aedda.DbConfig.TlsCfgOptions.SecretsStore = &AppEndpointDbTlsCfgLocSecretsStore{}

									if cltss.DbServerCaPath != nil {
										aedda.DbConfig.TlsCfgOptions.SecretsStore.DbServerCaPath = &SecretsStoreCredX509Cert{
											PublicKeyPath:  types.StringValue(cltss.DbServerCaPath.PublicKeyPath),
											SecretsStoreId: types.StringValue(cltss.DbServerCaPath.SecretsStoreId),
										}
									}
									if cltss.ProxyServerCertPath != nil {
										aedda.DbConfig.TlsCfgOptions.SecretsStore.ProxyServerCertPath = &SecretsStoreCredX509Pair{
											CaCertPath:     types.StringValue(cltss.ProxyServerCertPath.CaCertPath),
											PrivateKeyPath: types.StringValue(cltss.ProxyServerCertPath.PrivateKeyPath),
											PublicKeyPath:  types.StringValue(cltss.ProxyServerCertPath.PublicKeyPath),
											SecretsStoreId: types.StringValue(cltss.ProxyServerCertPath.SecretsStoreId),
										}
									}
								}
							}
						}
					}

					dataEp.Endpoint.Attributes.DbAttributes = aedda
				}

			default:
				dda, ok := ae.Attributes.(*corecfgclient.AppEndpointDefaultDbAttributes)
				if ok && dda != nil {
					dataEp.Endpoint.Attributes.DbAttributes = &AppEndpointDefaultDbAttributes{
						UbClient: types.StringValue(dda.UbClient),
						DbProxy:  types.StringValue(dda.DbProxy),
						Region:   types.StringValue(dda.Region),
						StartUri: types.StringValue(dda.StartUri),
						DbConfig: nil,
					}

					if dda.DbConfig != nil {
						dataEp.Endpoint.Attributes.DbAttributes.DbConfig = &AppEndpointDbAttributesDbConfig{}
						if dda.DbConfig.TlsConfig != nil {
							dataEp.Endpoint.Attributes.DbAttributes.DbConfig.TlsConfig = AppEndpointDbTlsConfig{
								CertId: types.StringValue(dda.DbConfig.TlsConfig.CertId),
								DbCA:   types.StringValue(dda.DbConfig.TlsConfig.DbCA),
							}
						}
						if dda.DbConfig.TlsCfgOptions != nil {
							dataEp.Endpoint.Attributes.DbAttributes.DbConfig.TlsCfgOptions = AppEndpointDbTlsConfigOptions{
								CfgLocType: types.StringValue(dda.DbConfig.TlsCfgOptions.CfgLocType),
							}
							if dda.DbConfig.TlsCfgOptions.CfgLocation != nil &&
								dda.DbConfig.TlsCfgOptions.CfgLocType == "SECRETS_STORE" {

								cltss, ok := dda.DbConfig.TlsCfgOptions.CfgLocation.(*corecfgclient.AppEndpointDbTlsCfgLocSecretsStore)
								if ok && cltss != nil {
									dataEp.Endpoint.Attributes.DbAttributes.DbConfig.TlsCfgOptions.SecretsStore = &AppEndpointDbTlsCfgLocSecretsStore{}

									if cltss.DbServerCaPath != nil {
										dataEp.Endpoint.Attributes.DbAttributes.DbConfig.TlsCfgOptions.SecretsStore.DbServerCaPath = &SecretsStoreCredX509Cert{
											PublicKeyPath:  types.StringValue(cltss.DbServerCaPath.PublicKeyPath),
											SecretsStoreId: types.StringValue(cltss.DbServerCaPath.SecretsStoreId),
										}
									}
									if cltss.ProxyServerCertPath != nil {
										dataEp.Endpoint.Attributes.DbAttributes.DbConfig.TlsCfgOptions.SecretsStore.ProxyServerCertPath = &SecretsStoreCredX509Pair{
											CaCertPath:     types.StringValue(cltss.ProxyServerCertPath.CaCertPath),
											PrivateKeyPath: types.StringValue(cltss.ProxyServerCertPath.PrivateKeyPath),
											PublicKeyPath:  types.StringValue(cltss.ProxyServerCertPath.PublicKeyPath),
											SecretsStoreId: types.StringValue(cltss.ProxyServerCertPath.SecretsStoreId),
										}
									}
								}
							}
						}
					}
				} else {
					da, ok := ae.Attributes.(*corecfgclient.AppEndpointDefaultAttributes)
					if ok && da != nil {
						dataEp.Endpoint.Attributes.DefaultAttributes = &AppEndpointDefaultAttributes{
							StartUri: types.StringValue(da.StartUri),
						}
					}
				}
			}
		}

		if ae.BrowserAccessSettings != nil {
			bas := ae.BrowserAccessSettings

			dataEp.BaSettings = &BrowserAccessSettings{
				//Id:             nil,
				AppEndpointId: types.StringValue(bas.AppEndpointId),
				//	Port:             ,
				UrlAlias:         types.BoolValue(bas.UrlAlias),
				HostingType:      types.StringValue(bas.HostingType),
				ResourceType:     types.StringValue(bas.ResourceType),
				UrlAliasSettings: nil,
				BaHttpAttribs:    nil,
				BaHttpsAttribs:   nil,
			}

			// NOTE: Read doesn't return the port number
			if len(curr.Endpoints) >= i {
				currEp := curr.Endpoints[i]
				if currEp != nil && currEp.BaSettings != nil {
					dataEp.BaSettings.Port = currEp.BaSettings.Port
				}
			}

			if bas.UrlAliasSettings != nil {
				dataEp.BaSettings.UrlAliasSettings = &BaUrlAliasSettings{
					CertId: types.StringValue(bas.UrlAliasSettings.CertId),
					Cname:  types.StringValue(bas.UrlAliasSettings.Cname),
				}
			}
			if bas.Attributes != nil {
				switch ae.Protocol {
				case corecfgclient.AppEndpointProtocolHTTP:
					baHttp := bas.Attributes.(*corecfgclient.BaHttpAttributes)
					dataEp.BaSettings.BaHttpAttribs = &BaHttpAttributes{
						Headers:  ConvMapStringArrayTypes(baHttp.Headers),
						StartUri: types.StringValue(baHttp.StartUri),
					}
				case corecfgclient.AppEndpointProtocolHTTPS:
					baHttps := bas.Attributes.(*corecfgclient.BaHttpsAttributes)
					dataEp.BaSettings.BaHttpsAttribs = &BaHttpsAttributes{
						Headers:  ConvMapStringArrayTypes(baHttps.Headers),
						StartUri: types.StringValue(baHttps.StartUri),
					}
				}
			}
		}
	}

	if len(car.Networks) > 0 {
		data.NetworkIds = make([]types.String, len(car.Networks))
		for i := 0; i < len(car.Networks); i++ {
			data.NetworkIds[i] = types.StringValue(car.Networks[i].Id)
		}
	} else {
		data.NetworkIds = nil
	}

	if len(car.AppConnectors) > 0 {
		data.ConnectorIds = make([]types.String, len(car.AppConnectors))
		for i := 0; i < len(car.AppConnectors); i++ {
			data.ConnectorIds[i] = types.StringValue(car.AppConnectors[i].Id)
		}
	} else {
		data.ConnectorIds = nil
	}

	if len(car.AuthProviders) > 0 {
		data.AuthProviderIds = make([]types.String, len(car.AuthProviders))
		for i := 0; i < len(car.AuthProviders); i++ {
			data.AuthProviderIds[i] = types.StringValue(car.AuthProviders[i].Id)
		}
	} else {
		data.AuthProviderIds = nil
	}

	if len(car.AppLaunchpads) > 0 {
		data.AppLaunchpadIds = make([]types.String, len(car.AppLaunchpads))
		for i := 0; i < len(car.AppLaunchpads); i++ {
			data.AppLaunchpadIds[i] = types.StringValue(car.AppLaunchpads[i].Id)
		}
	} else {
		data.AppLaunchpadIds = nil
	}

	if len(car.AppSecretsStores) > 0 {
		data.SecretsStores = make([]*AppSecretsStore, len(car.AppSecretsStores))
	} else {
		data.SecretsStores = nil
	}
	for i := 0; i < len(car.AppSecretsStores); i++ {
		ss := &car.AppSecretsStores[i]

		if ss.Attributes == nil || ss.Attributes.Attributes == nil {
			continue
		}

		dataSS := &AppSecretsStore{
			SecretsStoreId: types.StringValue(ss.SecretsStoreId),
			Attributes: &AppSecretsStoreAttributes{
				CredentialType: types.StringValue(string(ss.Attributes.CredentialType)),
				PrincipalScope: types.StringValue(ss.Attributes.PrincipalScope),
			},
		}
		data.SecretsStores[i] = dataSS

		switch ss.Attributes.CredentialType {
		case corecfgclient.CredentialApiKey:
			aka, ok := ss.Attributes.Attributes.(*corecfgclient.ApiKeyAttributes)
			if ok && aka != nil {
				dataSS.Attributes.ApiKeyAttribs = &ApiKeyAttributes{
					Keys: make([]Key, len(aka.Keys)),
				}
				for j := 0; j < len(aka.Keys); j++ {
					k1 := &dataSS.Attributes.ApiKeyAttribs.Keys[j]
					k2 := &aka.Keys[j]

					k1.Name = types.StringValue(k2.Name)
					k1.Value = types.StringValue(k2.Value)
				}
			}

		case corecfgclient.CredentialJwt:
			jka, ok := ss.Attributes.Attributes.(*corecfgclient.JwtAttributes)
			if ok && jka != nil {
				dataSS.Attributes.JwtAttribs = &JwtAttributes{
					Keys: make([]Key, len(jka.Keys)),
				}
				for j := 0; j < len(jka.Keys); j++ {
					k1 := &dataSS.Attributes.JwtAttribs.Keys[j]
					k2 := &jka.Keys[j]

					k1.Name = types.StringValue(k2.Name)
					k1.Value = types.StringValue(k2.Value)
				}
			}

		case corecfgclient.CredentialUserPswd:
			up, ok := ss.Attributes.Attributes.(*corecfgclient.UserPswdAttributes)
			if ok && up != nil {
				dataSS.Attributes.UserPswdAttribs = &UserPswdAttributes{
					User: Key{
						Name:  types.StringValue(up.User.Name),
						Value: types.StringValue(up.User.Value),
					},
					Pswd: Key{
						Name:  types.StringValue(up.Pswd.Name),
						Value: types.StringValue(up.Pswd.Value),
					},
				}
			}

		case corecfgclient.CredentialCert:
			ca, ok := ss.Attributes.Attributes.(*corecfgclient.AppSecretsStoreCertAttributes)
			if ok && ca != nil {
				dataSS.Attributes.CertAttribs = &AppSecretsStoreCertAttributes{
					PrivateKeyPath: types.StringValue(ca.PrivateKeyPath),
					PublicKeyPath:  types.StringValue(ca.PublicKeyPath),
					CaCertPath:     types.StringValue(ca.CaCertPath),
				}
			}
		}
	}

	if len(car.Roles) > 0 {
		data.Roles = make([]*AppRole, len(car.Roles))
		for i := 0; i < len(car.Roles); i++ {
			r := &car.Roles[i]

			dataRole := &AppRole{
				RoleId:     types.StringValue(r.Id),
				Attributes: nil,
			}

			if r.AppRoleAttributes != nil {
				dataRole.Attributes = &AppRoleAttributes{
					DbUsers: ConvStringTypesArray(r.AppRoleAttributes.DbUsers),
				}
			}
			data.Roles[i] = dataRole
		}
	} else {
		data.Roles = nil
	}

	if len(car.AppTags) > 0 {
		data.AppTagIds = make([]types.String, len(car.AppTags))
		for i := 0; i < len(car.AppTags); i++ {
			data.AppTagIds[i] = types.StringValue(car.AppTags[i].Id)
		}
	} else {
		data.AppTagIds = nil
	}

	return true
}

func (ar *AppResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var curr, data AppResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &curr)...)

	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.AddWarning("curr data", spewCfg.Sdump(curr))

	appId := ConvTypesString(curr.Id)
	if len(appId) <= 0 {
		resp.Diagnostics.AddError("App id nil", fmt.Sprintf("%v", curr))
		return
	}

	data.Id = curr.Id
	if !appReadHelper(ctx, req, resp, appId, &curr, &data, ar.appsApiSvc) {
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func fillAppEndpointAttribs(ep *AppEndpointRaw) (attribs corecfgclient.IsAppEndpointAttributes) {
	if ep.Endpoint.Attributes == nil {
		return
	}

	proto := corecfgclient.AppEndpointProtocol(ConvTypesString(ep.Endpoint.Protocol))

	switch {
	case proto == corecfgclient.AppEndpointProtocolSSH:
		if ep.Endpoint.Attributes.SSHAttributes != nil {
			attribs = &corecfgclient.AppEndpointSshAttributes{
				UbClient:   ConvTypesString(ep.Endpoint.Attributes.SSHAttributes.UbClient),
				SshProxy:   ConvTypesString(ep.Endpoint.Attributes.SSHAttributes.SshProxy),
				BypassList: ConvTypesArrayString(ep.Endpoint.Attributes.SSHAttributes.BypassList),
			}
		}
	case proto == corecfgclient.AppEndpointProtocolK8S:
		if ep.Endpoint.Attributes.K8SAttributes != nil {
			attribs = &corecfgclient.AppEndpointK8SAttributes{
				K8sUbClient:           ConvTypesString(ep.Endpoint.Attributes.K8SAttributes.K8SUbClient),
				K8sAuthenticationType: ConvTypesString(ep.Endpoint.Attributes.K8SAttributes.K8SAuthenticationType),
				K8sAccessToken:        ConvTypesString(ep.Endpoint.Attributes.K8SAttributes.K8SAccessToken),
				K8sUserIdentity:       ConvTypesString(ep.Endpoint.Attributes.K8SAttributes.K8SUserIdentity),
			}
		}
	case proto == corecfgclient.AppEndpointProtocolRDP:
		if ep.Endpoint.Attributes.RDPAttributes != nil {
			attribs = &corecfgclient.AppEndpointRdpAttributes{
				UbClient: ConvTypesString(ep.Endpoint.Attributes.RDPAttributes.UbClient),
			}
		}
	case proto == corecfgclient.AppEndpointProtocolVNC:
		if ep.Endpoint.Attributes.VNCAttributes != nil {
			attribs = &corecfgclient.AppEndpointVncAttributes{
				UbClient: ConvTypesString(ep.Endpoint.Attributes.VNCAttributes.UbClient),
			}
		}
	case ep.Endpoint.Attributes.DbAttributes != nil:
		switch proto {
		case corecfgclient.AppEndpointProtocolMySQL:
			attribs = &corecfgclient.AppEndpointMySqlAttributes{
				UbClient: ConvTypesString(ep.Endpoint.Attributes.DbAttributes.UbClient),
				DbProxy:  ConvTypesString(ep.Endpoint.Attributes.DbAttributes.DbProxy),
				DbConfig: &corecfgclient.AppEndpointMySqlAttributesDbConfig{
					TlsConfig: &corecfgclient.AppEndpointMySqlTlsConfig{
						CertId: ConvTypesString(ep.Endpoint.Attributes.DbAttributes.DbConfig.TlsConfig.CertId),
						DbCA:   ConvTypesString(ep.Endpoint.Attributes.DbAttributes.DbConfig.TlsConfig.DbCA),
					},
				},
			}
		case corecfgclient.AppEndpointProtocolPostgres, corecfgclient.AppEndpointProtocolAuroraPostgres:
			attribs = &corecfgclient.AppEndpointPostgresAttributes{
				UbClient: ConvTypesString(ep.Endpoint.Attributes.DbAttributes.UbClient),
				DbProxy:  ConvTypesString(ep.Endpoint.Attributes.DbAttributes.DbProxy),
				DbConfig: &corecfgclient.AppEndpointPostgresAttributesDbConfig{
					TlsConfig: &corecfgclient.AppEndpointPostgresTlsConfig{
						CertId: ConvTypesString(ep.Endpoint.Attributes.DbAttributes.DbConfig.TlsConfig.CertId),
						DbCA:   ConvTypesString(ep.Endpoint.Attributes.DbAttributes.DbConfig.TlsConfig.DbCA),
					},
				},
			}
		default:
			attribs = &corecfgclient.AppEndpointDefaultDbAttributes{
				UbClient: ConvTypesString(ep.Endpoint.Attributes.DbAttributes.UbClient),
				DbProxy:  ConvTypesString(ep.Endpoint.Attributes.DbAttributes.DbProxy),
				Region:   ConvTypesString(ep.Endpoint.Attributes.DbAttributes.Region),
				StartUri: ConvTypesString(ep.Endpoint.Attributes.DbAttributes.StartUri),
				DbConfig: &corecfgclient.AppEndpointPostgresAttributesDbConfig{
					TlsConfig: &corecfgclient.AppEndpointPostgresTlsConfig{
						CertId: ConvTypesString(ep.Endpoint.Attributes.DbAttributes.DbConfig.TlsConfig.CertId),
						DbCA:   ConvTypesString(ep.Endpoint.Attributes.DbAttributes.DbConfig.TlsConfig.DbCA),
					},
				},
			}
		}
	case ep.Endpoint.Attributes.IdpGroupAttributes != nil &&
		(!IsTypesStringEmpty(ep.Endpoint.Attributes.IdpGroupAttributes.GroupId) ||
			!IsTypesStringEmpty(ep.Endpoint.Attributes.IdpGroupAttributes.GroupName)):
		attribs = &corecfgclient.AppEndpointIdpGroupAttributes{
			GroupId:   ConvTypesString(ep.Endpoint.Attributes.IdpGroupAttributes.GroupId),
			GroupName: ConvTypesString(ep.Endpoint.Attributes.IdpGroupAttributes.GroupName),
		}
	case ep.Endpoint.Attributes.DefaultAttributes != nil && !IsTypesStringEmpty(ep.Endpoint.Attributes.DefaultAttributes.StartUri):
		attribs = &corecfgclient.AppEndpointDefaultAttributes{
			StartUri: ConvTypesString(ep.Endpoint.Attributes.DefaultAttributes.StartUri),
		}
	}

	return
}

func fillBrowserAccessAttribs(ep *AppEndpointRaw) (attribs interface{}) {
	if ep.BaSettings.BaHttpAttribs != nil {
		attribs = &corecfgclient.BaHttpAttributes{
			Headers:  ConvTypesMapStringArray(ep.BaSettings.BaHttpAttribs.Headers),
			StartUri: ConvTypesString(ep.BaSettings.BaHttpAttribs.StartUri),
		}
	} else if ep.BaSettings.BaHttpsAttribs != nil {
		attribs = &corecfgclient.BaHttpsAttributes{
			Headers:  ConvTypesMapStringArray(ep.BaSettings.BaHttpsAttribs.Headers),
			StartUri: ConvTypesString(ep.BaSettings.BaHttpsAttribs.StartUri),
		}
	} /*else if ep.BaSettings.BaSshAttribs != nil {
		attribs = &corecfgclient.BaSshAttributes{
			MaxConnections: ConvTypesInt64(ep.BaSettings.BaSshAttribs.MaxConnections),
			StartUri:       ConvTypesString(ep.BaSettings.BaSshAttribs.StartUri),
		}
	}*/
	return
}

func addrStrFromEndpoint(ep *AppEndpointRaw) string {
	addr := ""
	if ep.Endpoint.Addr != nil {
		addr = ConvTypesString(ep.Endpoint.Addr.Value)
	}
	if ep.Endpoint.Port != nil {
		addr += ":" + ConvTypesString(ep.Endpoint.Port.Value)
	}
	return addr
}

func appUpdateHelper(ctx context.Context, req resource.UpdateRequest,
	resp *resource.UpdateResponse, curr, data *AppResourceModel,
	appsApiSvc *corecfgclient.AppsApiService) (success bool) {

	appId := ConvTypesString(curr.Id)
	if len(appId) <= 0 {
		resp.Diagnostics.AddError("App-id nil", fmt.Sprintf("%v", curr))
		return
	}

	compReqsCurr := createBackendAppObj(curr)
	compReqsNew := createBackendAppObj(data)
	currJson, _ := json.Marshal(compReqsCurr)
	dataJson, _ := json.Marshal(compReqsNew)
	//resp.Diagnostics.AddWarning("jsons", fmt.Sprintf("curr: %s, data: %s", string(currJson), string(dataJson)))
	tflog.Trace(ctx, fmt.Sprintf("curr: %s, data: %s", string(currJson), string(dataJson)))
	if reflect.DeepEqual(currJson, dataJson) {
		resp.Diagnostics.AddWarning("No changes", fmt.Sprintf("No changes in data"))
		// Save updated data into Terraform state
		resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
		return
	}
	data.Id = curr.Id

	var compReqs []corecfgclient.CompositeAppResourceRaw

	// APP
	ua := &corecfgclient.UpdateApp{
		ApprovalConfig:    nil,
		AssetId:           ConvTypesString(data.AssetId),
		Attributes:        nil, //???
		Authentication:    nil,
		Description:       ConvTypesString(data.Description),
		IsAuthnEnabled:    ConvTypesBool(data.IsAuthnEnabled),
		ManagedBy:         ConvTypesString(data.ManagedBy),
		Name:              ConvTypesString(data.Name),
		ServiceProviderId: ConvTypesString(data.ServiceProviderId),
		ServiceType:       ConvTypesString(data.ServiceType),
		SubCategory:       ConvTypesString(data.SubCategory),
		Type_:             ConvTypesString(data.AppType),
	}

	compRs := corecfgclient.CompositeAppResourceRaw{
		Body:        ua,
		Method:      http.MethodPatch,
		ReferenceId: "app-raw-patch",
		Type_:       "APP",
	}
	compReqs = []corecfgclient.CompositeAppResourceRaw{compRs}

	// APPLAUNCHPAD
	dels := make(map[string]struct{})
	adds := make(map[string]struct{})
	for _, alid := range curr.AppLaunchpadIds {
		dels[ConvTypesString(alid)] = struct{}{}
	}
	for _, alid := range data.AppLaunchpadIds {
		alidStr := ConvTypesString(alid)
		_, ok := dels[alidStr]
		if ok {
			delete(dels, alidStr)
		} else {
			adds[alidStr] = struct{}{}
		}
	}
	if len(dels) > 0 {
		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        ConvMapStringToArr(dels),
			Method:      http.MethodDelete,
			ReferenceId: "app_launchpadId_DELETE",
			Type_:       "APPLAUNCHPAD",
		}
		compReqs = append(compReqs, compRs)
	}
	if len(adds) > 0 {
		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        ConvMapStringToArr(adds),
			Method:      http.MethodPost,
			ReferenceId: "app_launchpadId_POST",
			Type_:       "APPLAUNCHPAD",
		}
		compReqs = append(compReqs, compRs)
	}

	// APPENDPOINT
	var addEps []*AppEndpointRaw
	updEps := make(map[string]*AppEndpointRaw)
	delEps := make(map[string]struct{})
	newEpByAddr := make(map[string]*AppEndpointRaw)
	for _, ep := range data.Endpoints {
		if ep == nil ||
			(ep.Endpoint.Addr == nil && ep.Endpoint.Port == nil) {
			continue
		}

		addr := addrStrFromEndpoint(ep)
		newEpByAddr[addr] = ep
	}
	for _, ep := range curr.Endpoints {
		if ep == nil {
			continue
		}
		delEps[ConvTypesString(ep.Endpoint.AppEndpointId)] = struct{}{}
	}
	if len(data.Endpoints) == 1 && len(curr.Endpoints) == 1 {
		currEp := curr.Endpoints[0]
		if currEp != nil {
			epId := ConvTypesString(currEp.Endpoint.AppEndpointId)
			delete(delEps, epId)

			newEp := data.Endpoints[0]
			newEp.Endpoint.AppEndpointId = types.StringValue(epId)
			if !reflect.DeepEqual(currEp, newEp) {
				updEps[epId] = newEp
			}
		}
	} else {
		currEpByAddr := make(map[string]*AppEndpointRaw)
		for _, ep := range curr.Endpoints {
			if ep == nil ||
				(ep.Endpoint.Addr == nil && ep.Endpoint.Port == nil) {
				continue
			}

			addr := ""
			if ep.Endpoint.Addr != nil {
				addr = ConvTypesString(ep.Endpoint.Addr.Value)
			}
			if ep.Endpoint.Port != nil {
				addr += ":" + ConvTypesString(ep.Endpoint.Port.Value)
			}
			currEpByAddr[addr] = ep
		}

		for _, ep := range data.Endpoints {
			if ep == nil ||
				(ep.Endpoint.Addr == nil && ep.Endpoint.Port == nil) {
				continue
			}

			addr := ""
			if ep.Endpoint.Addr != nil {
				addr = ConvTypesString(ep.Endpoint.Addr.Value)
			}
			if ep.Endpoint.Port != nil {
				addr += ":" + ConvTypesString(ep.Endpoint.Port.Value)
			}
			currEp, ok := currEpByAddr[addr]
			if ok {
				epId := ConvTypesString(currEp.Endpoint.AppEndpointId)
				delete(delEps, epId)
				updEps[epId] = ep
				ep.Endpoint.AppEndpointId = types.StringValue(epId)
			} else {
				addEps = append(addEps, ep)
			}
		}
	}
	currEps := make(map[string]*AppEndpointRaw)
	for _, ep := range curr.Endpoints {
		if ep == nil {
			continue
		}

		epId := ConvTypesString(ep.Endpoint.AppEndpointId)
		currEps[epId] = ep
	}
	if len(delEps) > 0 {
		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        ConvMapStringToArr(dels),
			Method:      http.MethodDelete,
			ReferenceId: "app_endpoint_DELETE",
			Type_:       "APPENDPOINT",
		}
		compReqs = append(compReqs, compRs)
	}
	if len(updEps) > 0 {
		var updAes []*corecfgclient.UpdateAppEndpointRaw

		for _, ep := range updEps {
			if ep == nil {
				continue
			}

			updAe := &corecfgclient.UpdateAppEndpointRaw{
				Id:                    ConvTypesString(ep.Endpoint.AppEndpointId),
				AccessType:            ConvTypesString(ep.Endpoint.AccessType),
				Addr:                  nil,
				Attributes:            nil,
				OnboardingType:        ConvTypesString(ep.Endpoint.OnboardingType),
				BrowserAccessSettings: nil,
				Port:                  nil,
				Protocol:              ConvTypesString(ep.Endpoint.Protocol),
				ServiceTemplateId:     ConvTypesString(ep.Endpoint.ServiceTemplateId),
				Source:                ConvTypesString(ep.Endpoint.Source),
			}
			if ep.Endpoint.Addr != nil {
				updAe.Addr = &corecfgclient.AppEndpointAddr{
					Type_: ConvTypesString(ep.Endpoint.Addr.Type_),
					Value: ConvTypesString(ep.Endpoint.Addr.Value),
				}
			}
			if ep.Endpoint.Port != nil {
				updAe.Port = &corecfgclient.AppEndpointPort{
					Type_: ConvTypesString(ep.Endpoint.Port.Type_),
					Value: ConvTypesString(ep.Endpoint.Port.Value),
				}
			}

			if ep.Endpoint.Attributes != nil {
				updAe.Attributes = fillAppEndpointAttribs(ep)
			}

			currEp := currEps[ConvTypesString(ep.Endpoint.AppEndpointId)]

			if ep.BaSettings != nil {
				basUpdate := currEp != nil &&
					currEp.BaSettings != nil /*&& ep.BaSettings.Id.Equal(currEp.BaSettings.Id)*/
				if basUpdate {
					updBas := &corecfgclient.UpdateBrowserAccessSettings{
						UrlAlias:    ConvTypesBool(ep.BaSettings.UrlAlias),
						HostingType: ConvTypesString(ep.BaSettings.HostingType),
						Attributes:  fillBrowserAccessAttribs(ep),
						//ResourceType: ConvTypesString(ep.BaSettings.ResourceType),
					}
					updAe.BrowserAccessSettings = updBas
				} else {
					updBas := &corecfgclient.NewBrowserAccessSettings{
						UrlAlias:     ConvTypesBool(ep.BaSettings.UrlAlias),
						HostingType:  ConvTypesString(ep.BaSettings.HostingType),
						Attributes:   fillBrowserAccessAttribs(ep),
						ResourceType: ConvTypesString(ep.BaSettings.ResourceType),
					}
					updAe.BrowserAccessSettings = updBas
				}
			}
			updAes = append(updAes, updAe)
		}
		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        updAes,
			Method:      http.MethodPatch,
			ReferenceId: "appendpointpatch",
			Type_:       "APPENDPOINT",
		}
		compReqs = append(compReqs, compRs)
	}

	if len(addEps) > 0 {
		var newAppEps []*corecfgclient.UpdateAppEndpointRaw

		for _, ep := range addEps {
			if ep == nil {
				continue
			}

			newAppEp := &corecfgclient.UpdateAppEndpointRaw{
				Id:                    ConvTypesString(ep.Endpoint.AppEndpointId),
				AccessType:            ConvTypesString(ep.Endpoint.AccessType),
				Addr:                  nil,
				Attributes:            nil,
				OnboardingType:        ConvTypesString(ep.Endpoint.OnboardingType),
				BrowserAccessSettings: nil,
				Port:                  nil,
				Protocol:              ConvTypesString(ep.Endpoint.Protocol),
				ServiceTemplateId:     ConvTypesString(ep.Endpoint.ServiceTemplateId),
				Source:                ConvTypesString(ep.Endpoint.Source),
			}
			if ep.Endpoint.Addr != nil {
				newAppEp.Addr = &corecfgclient.AppEndpointAddr{
					Type_: ConvTypesString(ep.Endpoint.Addr.Type_),
					Value: ConvTypesString(ep.Endpoint.Addr.Value),
				}
			}
			if ep.Endpoint.Port != nil {
				newAppEp.Port = &corecfgclient.AppEndpointPort{
					Type_: ConvTypesString(ep.Endpoint.Port.Type_),
					Value: ConvTypesString(ep.Endpoint.Port.Value),
				}
			}

			if ep.Endpoint.Attributes != nil {
				newAppEp.Attributes = fillAppEndpointAttribs(ep)
			}

			if ep.BaSettings != nil {
				newAppEp.BrowserAccessSettings = &corecfgclient.NewBrowserAccessSettings{
					UrlAlias:     ConvTypesBool(ep.BaSettings.UrlAlias),
					HostingType:  ConvTypesString(ep.BaSettings.HostingType),
					ResourceType: ConvTypesString(ep.BaSettings.ResourceType),
					Attributes:   fillBrowserAccessAttribs(ep),
				}
			}
			newAppEps = append(newAppEps, newAppEp)
		}
		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        newAppEps,
			Method:      http.MethodPost,
			ReferenceId: "appendpointpost",
			Type_:       "APPENDPOINT",
		}
		compReqs = append(compReqs, compRs)
	}

	if len(data.Roles) > 0 {
		var appRoles []corecfgclient.UpdateAppRole
		for _, role := range data.Roles {
			if role == nil {
				continue
			}

			updAppRole := &corecfgclient.UpdateAppRole{
				Attributes: nil,
				RoleId:     ConvTypesString(role.RoleId),
			}

			if role.Attributes != nil && len(role.Attributes.DbUsers) > 0 {
				updAppRole.Attributes = &corecfgclient.AppRoleAttributes{}
				for _, dbUser := range role.Attributes.DbUsers {
					updAppRole.Attributes.DbUsers = append(updAppRole.Attributes.DbUsers, ConvTypesString(dbUser))
				}
			}

			appRoles = append(appRoles, *updAppRole)
		}

		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        appRoles,
			Method:      http.MethodPatch,
			ReferenceId: "app_approles_PATCH",
			Type_:       "APPROLE",
		}
		compReqs = append(compReqs, compRs)
	} /*else {
		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        nil,
			Method:      http.MethodDelete,
			ReferenceId: "app_approles_DELETE",
			Type_:       "APPROLE",
		}
		compReqs = append(compReqs, compRs)
	}*/

	if len(data.SecretsStores) > 0 {
		var sss []*corecfgclient.UpdateAppSecretsStore

		for _, ss := range data.SecretsStores {
			if ss == nil || ss.Attributes == nil {
				continue
			}

			newAppSecretStore := &corecfgclient.UpdateAppSecretsStore{
				Attributes: &corecfgclient.AppSecretsStoreAttributes{
					CredentialType: corecfgclient.CredentialType(ConvTypesString(ss.Attributes.CredentialType)),
					PrincipalScope: ConvTypesString(ss.Attributes.PrincipalScope),
				},
			}

			switch ConvTypesString(ss.Attributes.CredentialType) {
			case "APIKEY":
				if ss.Attributes.ApiKeyAttribs != nil &&
					len(ss.Attributes.ApiKeyAttribs.Keys) > 0 {
					aka := &corecfgclient.ApiKeyAttributes{Keys: make([]corecfgclient.Key, len(ss.Attributes.ApiKeyAttribs.Keys))}
					for i := 0; i < len(ss.Attributes.ApiKeyAttribs.Keys); i++ {
						k1 := &aka.Keys[i]
						k2 := &ss.Attributes.ApiKeyAttribs.Keys[i]

						k1.Name = ConvTypesString(k2.Name)
						k1.Value = ConvTypesString(k2.Value)
					}
					newAppSecretStore.Attributes.Attributes = aka
				}

			case "JWT":
				if ss.Attributes.JwtAttribs != nil &&
					len(ss.Attributes.JwtAttribs.Keys) > 0 {
					jka := &corecfgclient.JwtAttributes{Keys: make([]corecfgclient.Key, len(ss.Attributes.JwtAttribs.Keys))}
					for i := 0; i < len(ss.Attributes.JwtAttribs.Keys); i++ {
						k1 := &jka.Keys[i]
						k2 := &ss.Attributes.JwtAttribs.Keys[i]

						k1.Name = ConvTypesString(k2.Name)
						k1.Value = ConvTypesString(k2.Value)
					}
					newAppSecretStore.Attributes.Attributes = jka
				}

			case "USERPSWD":
				if ss.Attributes.UserPswdAttribs != nil {
					newAppSecretStore.Attributes.Attributes = &corecfgclient.UserPswdAttributes{
						User: &corecfgclient.Key{
							Name:  ConvTypesString(ss.Attributes.UserPswdAttribs.User.Name),
							Value: ConvTypesString(ss.Attributes.UserPswdAttribs.User.Value),
						},
						Pswd: &corecfgclient.Key{
							Name:  ConvTypesString(ss.Attributes.UserPswdAttribs.Pswd.Name),
							Value: ConvTypesString(ss.Attributes.UserPswdAttribs.Pswd.Value),
						},
					}
				}
			case "CERT":
				if ss.Attributes.CertAttribs != nil {
					newAppSecretStore.Attributes.Attributes = &corecfgclient.AppSecretsStoreCertAttributes{
						PrivateKeyPath: ConvTypesString(ss.Attributes.CertAttribs.PrivateKeyPath),
						PublicKeyPath:  ConvTypesString(ss.Attributes.CertAttribs.PublicKeyPath),
						CaCertPath:     ConvTypesString(ss.Attributes.CertAttribs.CaCertPath),
					}
				}
			}

			sss = append(sss, newAppSecretStore)
		}

		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        sss,
			Method:      http.MethodPatch,
			ReferenceId: "app_ss_PATCH",
			Type_:       "APPSECRETSSTORE",
		}
		compReqs = append(compReqs, compRs)
	}

	dels = make(map[string]struct{})
	adds = make(map[string]struct{})
	for _, nId := range curr.NetworkIds {
		dels[ConvTypesString(nId)] = struct{}{}
	}
	for _, nId := range data.NetworkIds {
		nIdStr := ConvTypesString(nId)
		_, ok := dels[nIdStr]
		if ok {
			delete(dels, nIdStr)
		} else {
			adds[nIdStr] = struct{}{}
		}
	}
	if len(dels) > 0 {
		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        ConvMapStringToArr(dels),
			Method:      http.MethodDelete,
			ReferenceId: "app_network-DELETE",
			Type_:       "NETWORK",
		}
		compReqs = append(compReqs, compRs)
	}
	if len(adds) > 0 {
		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        ConvMapStringToArr(adds),
			Method:      http.MethodPost,
			ReferenceId: "app-network-POST",
			Type_:       "NETWORK",
		}
		compReqs = append(compReqs, compRs)
	}

	dels = make(map[string]struct{})
	adds = make(map[string]struct{})
	for _, cId := range curr.ConnectorIds {
		dels[ConvTypesString(cId)] = struct{}{}
	}
	for _, cId := range data.ConnectorIds {
		cIdStr := ConvTypesString(cId)
		_, ok := dels[cIdStr]
		if ok {
			delete(dels, cIdStr)
		} else {
			adds[cIdStr] = struct{}{}
		}
	}
	if len(dels) > 0 {
		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        ConvMapStringToArr(dels),
			Method:      http.MethodDelete,
			ReferenceId: "app-connector-DELETE",
			Type_:       "APPCONNECTOR",
		}
		compReqs = append(compReqs, compRs)
	}
	if len(adds) > 0 {
		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        ConvMapStringToArr(adds),
			Method:      http.MethodPost,
			ReferenceId: "app-connector-POST",
			Type_:       "APPCONNECTOR",
		}
		compReqs = append(compReqs, compRs)
	}

	dels = make(map[string]struct{})
	adds = make(map[string]struct{})
	for _, apId := range curr.AuthProviderIds {
		dels[ConvTypesString(apId)] = struct{}{}
	}
	for _, apId := range data.AuthProviderIds {
		apIdStr := ConvTypesString(apId)
		_, ok := dels[apIdStr]
		if ok {
			delete(dels, apIdStr)
		} else {
			adds[apIdStr] = struct{}{}
		}
	}
	if len(dels) > 0 {
		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        ConvMapStringToArr(dels),
			Method:      http.MethodDelete,
			ReferenceId: "app-authprovider-DELETE",
			Type_:       "AUTHPROVIDER",
		}
		compReqs = append(compReqs, compRs)
	}
	if len(adds) > 0 {
		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        ConvMapStringToArr(adds),
			Method:      http.MethodPost,
			ReferenceId: "app-authprovider-POST",
			Type_:       "AUTHPROVIDER",
		}
		compReqs = append(compReqs, compRs)
	}

	dels = make(map[string]struct{})
	adds = make(map[string]struct{})
	for _, tId := range curr.AppTagIds {
		dels[ConvTypesString(tId)] = struct{}{}
	}
	for _, tId := range data.AppTagIds {
		tIdStr := ConvTypesString(tId)
		_, ok := dels[tIdStr]
		if ok {
			delete(dels, tIdStr)
		} else {
			adds[tIdStr] = struct{}{}
		}
	}
	if len(dels) > 0 {
		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        ConvMapStringToArr(dels),
			Method:      http.MethodDelete,
			ReferenceId: "app-tag-DELETE",
			Type_:       "APPTAG",
		}
		compReqs = append(compReqs, compRs)
	}
	if len(adds) > 0 {
		compRs = corecfgclient.CompositeAppResourceRaw{
			Body:        ConvMapStringToArr(adds),
			Method:      http.MethodPost,
			ReferenceId: "app-tag-POST",
			Type_:       "APPTAG",
		}
		compReqs = append(compReqs, compRs)
	}

	apiResp, httpResp, err := appsApiSvc.CompositeAppUpdate(ctx, compReqs, appId)
	if err != nil {
		resp.Diagnostics.AddError("Client Error", fmt.Sprintf("Unable to update app, got error: %s", err))
		return
	}

	if httpResp == nil {
		resp.Diagnostics.AddError("unexpected response from API", fmt.Sprintf("%v", httpResp))
		return
	}
	if httpResp.StatusCode != 200 {
		resp.Diagnostics.AddError("unexpected response from API. Got an unexpected response code %v", fmt.Sprintf("%d", httpResp.StatusCode))
		return
	}

	resp.Diagnostics.AddWarning("Update resp", spewCfg.Sdump(apiResp))

	if apiResp.Data == nil || apiResp.Data.App == nil {
		resp.Diagnostics.AddError("unexpected response from API. No response body", fmt.Sprintf("%v", apiResp))
		return
	}

	for i := 0; i < len(apiResp.Data.AppEndpoints); i++ {
		ep := &apiResp.Data.AppEndpoints[i]

		addr := ""
		if ep.Addr != nil {
			addr = ep.Addr.Value
		}
		if ep.Port != nil {
			addr += ":" + ep.Port.Value
		}

		newEp, ok := newEpByAddr[addr]
		if ok && newEp != nil &&
			len(ConvTypesString(newEp.Endpoint.AppEndpointId)) <= 0 {

			newEp.Endpoint.AppEndpointId = types.StringValue(ep.Id)
			if newEp.BaSettings != nil {
				newEp.BaSettings.AppEndpointId = types.StringValue(ep.Id)
			}
		}
	}

	return true
}

func (ar *AppResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var curr, data AppResourceModel

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

	if !appUpdateHelper(ctx, req, resp, &curr, &data, ar.appsApiSvc) {
		return
	}

	// Save updated data into Terraform state
	resp.Diagnostics.Append(resp.State.Set(ctx, &data)...)
}

func (ar *AppResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var data AppResourceModel

	// Read Terraform prior state data into the model
	resp.Diagnostics.Append(req.State.Get(ctx, &data)...)

	if resp.Diagnostics.HasError() {
		return
	}

	appId := ConvTypesString(data.Id)
	if len(appId) <= 0 {
		resp.Diagnostics.AddError("App-id nil", fmt.Sprintf("%v", data))
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

func (ar *AppResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}
