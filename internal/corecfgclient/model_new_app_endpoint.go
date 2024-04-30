/*
 * Configuration API.
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package corecfgclient

// NewAppEndpoint represents the request format for a new app endpoint to be created
type NewAppEndpoint struct {
	// The accesstype of an appendpoint NATIVE AppEndpointAccessTypeNative BROWSER AppEndpointAccessTypeBrowser
	AccessType string                   `json:"accessType,omitempty"`
	Addr       *AppEndpointAddr         `json:"addr"`
	Attributes *IsAppEndpointAttributes `json:"attributes,omitempty"`
	// The onboarding type for the application MANUAL AppEndpointOnboardingTypeManual DISCOVERY AppEndpointOnboardingTypeDiscovery
	OnboardingType string           `json:"onboardingType,omitempty"`
	Port           *AppEndpointPort `json:"port"`
	// The layer4 / layer 7  protcol of the app endpoint port HTTPS AppEndpointProtocolHTTPS HTTP AppEndpointProtocolHTTP SSH AppEndpointProtocolSSH K8S AppEndpointProtocolK8S TCP AppEndpointProtocolTcp UDP AppEndpointProtocolUdp RDP AppEndpointProtocolRDP VNC AppEndpointProtocolVNC S3 AppEndpointProtocolS3 MYSQL AppEndpointProtocolMySQL POSTGRES AppEndpointProtocolPostgres AURORA_MYSQL AppEndpointProtocolAuroraMySQL AURORA_POSTGRES AppEndpointProtocolAuroraPostgres SQLSERVER AppEndpointProtocolSqlServer MONGODB AppEndpointProtocolMongodb DYNAMODB AppEndpointProtocolDynamodb SNOWFLAKE AppEndpointProtocolSnowflake DATABRICKS AppEndpointProtocolDatabricks
	Protocol string `json:"protocol"`
	// The service template used if any for the application
	ServiceTemplateId string `json:"serviceTemplateId,omitempty"`
	// The source of an app endpoint MANUAL AppEndpointSourceManual DISCOVERED AppEndpointSourceeDiscovered
	Source string `json:"source"`
}
