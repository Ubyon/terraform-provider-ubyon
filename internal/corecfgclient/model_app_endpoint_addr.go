/*
 * Configuration API.
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package corecfgclient

// AppEndpointAddr represents the address in either IPAddress or FQDN format
type AppEndpointAddr struct {
	Type_ string `json:"type,omitempty"`
	Value string `json:"value,omitempty"`
}