/*
 * Configuration API.
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package corecfgclient

import (
	"encoding/json"
	"time"
)

// AppEndpointRaw represents the response format of app endpoint details
type AppEndpointRaw struct {
	// The accesstype of an appendpoint NATIVE AppEndpointAccessTypeNative BROWSER AppEndpointAccessTypeBrowser
	AccessType string           `json:"accessType,omitempty"`
	Addr       *AppEndpointAddr `json:"addr"`
	// The application Id that the app endpoint belong to
	AppId                 string                  `json:"appId"`
	Attributes            IsAppEndpointAttributes `json:"attributes,omitempty"`
	BrowserAccessSettings *BrowserAccessSettings  `json:"browserAccessSettings,omitempty"`
	// The creation timestamp of the auth provider
	Created time.Time `json:"created,omitempty"`
	// The Id of the app endpoint
	Id string `json:"id"`
	// The onboarding type for the application MANUAL AppEndpointOnboardingTypeManual DISCOVERY AppEndpointOnboardingTypeDiscovery
	OnboardingType string `json:"onboardingType,omitempty"`
	// The Id of the org associated with the app endpoint
	OrgId string           `json:"orgId,omitempty"`
	Port  *AppEndpointPort `json:"port"`
	// The layer4 / layer7 protcol of the app endpoint port HTTPS AppEndpointProtocolHTTPS HTTP AppEndpointProtocolHTTP SSH AppEndpointProtocolSSH K8S AppEndpointProtocolK8S TCP AppEndpointProtocolTcp UDP AppEndpointProtocolUdp RDP AppEndpointProtocolRDP VNC AppEndpointProtocolVNC S3 AppEndpointProtocolS3 MYSQL AppEndpointProtocolMySQL POSTGRES AppEndpointProtocolPostgres AURORA_MYSQL AppEndpointProtocolAuroraMySQL AURORA_POSTGRES AppEndpointProtocolAuroraPostgres SQLSERVER AppEndpointProtocolSqlServer MONGODB AppEndpointProtocolMongodb DYNAMODB AppEndpointProtocolDynamodb SNOWFLAKE AppEndpointProtocolSnowflake DATABRICKS AppEndpointProtocolDatabricks
	Protocol AppEndpointProtocol `json:"protocol"`
	// The service template used if any for the application
	ServiceTemplateId string `json:"serviceTemplateId,omitempty"`
	// The source of an app endpoint MANUAL AppEndpointSourceManual DISCOVERED AppEndpointSourceeDiscovered
	Source string `json:"source"`
	// The last updated timestamp of the app tag
	Updated time.Time `json:"updated,omitempty"`
	// The Id of the user by whom the org was last updated
	WhoUpdated string `json:"whoUpdated,omitempty"`
}

// AppEndpointDefaultAttributes represents the request format of default Attributes of an AppEndpoint
type AppEndpointDefaultAttributes struct {
	StartUri string `json:"startUri" db:"startUri" validate:"omitempty,uri"`
}

func (ae *AppEndpointRaw) UnmarshalJSON(bs []byte) error {
	var tae map[string]interface{}
	err := json.Unmarshal(bs, &tae)
	if err != nil {
		return err
	}

	type appEndpointRaw AppEndpointRaw
	fap := (*appEndpointRaw)(ae)

	p := ""
	pi, ok := tae["protocol"]
	if ok && pi != nil {
		p, ok = pi.(string)
	}

	if ok && len(p) > 0 {
		switch AppEndpointProtocol(p) {
		case AppEndpointProtocolSSH:
			fap.Attributes = &AppEndpointSshAttributes{}
		case AppEndpointProtocolK8S:
			fap.Attributes = &AppEndpointK8SAttributes{}
		case AppEndpointProtocolRDP:
			fap.Attributes = &AppEndpointRdpAttributes{}
		case AppEndpointProtocolVNC:
			fap.Attributes = &AppEndpointVncAttributes{}
		case AppEndpointProtocolMySQL,
			AppEndpointProtocolAuroraMySQL:
			fap.Attributes = &AppEndpointMySqlAttributes{}
		case AppEndpointProtocolPostgres,
			AppEndpointProtocolAuroraPostgres:
			fap.Attributes = &AppEndpointPostgresAttributes{}
		case AppEndpointProtocolSqlServer,
			AppEndpointProtocolMongodb,
			AppEndpointProtocolDynamodb,
			AppEndpointProtocolSnowflake,
			AppEndpointProtocolDatabricks,
			AppEndpointProtocolElasticSearch,
			AppEndpointProtocolRedis,
			AppEndpointProtocolCassandra,
			AppEndpointProtocolOpenSearch,
			AppEndpointProtocolClickHouse:
			fap.Attributes = &AppEndpointDefaultDbAttributes{}
		default:
			fap.Attributes = &AppEndpointDefaultAttributes{}
		}
	} else {
		fap.Attributes = &AppEndpointDefaultAttributes{}
	}

	err = json.Unmarshal(bs, &fap)
	if err != nil {
		return err
	}

	if ok && len(p) > 0 &&
		fap.BrowserAccessSettings != nil &&
		fap.BrowserAccessSettings.Attributes != nil {

		switch AppEndpointProtocol(p) {
		case AppEndpointProtocolHTTPS:
			fap.BrowserAccessSettings.Attributes = &BaHttpsAttributes{}
		case AppEndpointProtocolHTTP:
			fap.BrowserAccessSettings.Attributes = &BaHttpAttributes{}
		case AppEndpointProtocolSSH:
			fap.BrowserAccessSettings.Attributes = &BaSshAttributes{}
		}

		// Redo the unmarshal
		err = json.Unmarshal(bs, &fap)
		if err != nil {
			return err
		}
	}

	return nil
}
