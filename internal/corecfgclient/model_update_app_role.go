/*
 * Configuration API.
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package corecfgclient

// UpdateAppRole represents the request format for updating an app role association
type UpdateAppRole struct {
	// The Id of the org to which app to role is associated
	OrgId      string             `json:"OrgId,omitempty"`
	Attributes *AppRoleAttributes `json:"attributes,omitempty"`
	// The Id of the role to which app is associated
	RoleId string `json:"roleId"`
}
