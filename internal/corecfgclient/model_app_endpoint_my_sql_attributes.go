/*
 * Configuration API.
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package corecfgclient

// AppEndpointMySQLAttributes represents the request format of Attributes of an AppEndpoint
type AppEndpointMySqlAttributes struct {
	DbConfig *AppEndpointMySqlAttributesDbConfig `json:"dbConfig,omitempty"`
	DbProxy  string                              `json:"dbProxy,omitempty"`
	Region   string                              `json:"region,omitempty"`
	UbClient string                              `json:"ubClient,omitempty"`
}
