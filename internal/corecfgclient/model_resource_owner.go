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
	"time"
)

// ResourceOwner represents the response format of the details of the ResourceOwner
type ResourceOwner struct {
	// The ID of the associated app
	AppId string `json:"appId,omitempty"`
	// The attributes to be configured for the ResourceOwner
	Attributes []ResourceOwnerAttributes `json:"attributes,omitempty"`
	// The type of the ResourceOwner
	Channels []ResourceOwnerChannel `json:"channels,omitempty"`
	// The creation timestamp of the ResourceOwner
	Created time.Time `json:"created,omitempty"`
	// The description of the ResourceOwner
	Description string `json:"description,omitempty"`
	// The Id of the ResourceOwner
	Id string `json:"id"`
	// The name of the ResourceOwner
	Name string `json:"name"`
	// The Id of the org for which the ResourceOwner is associated
	OrgId string `json:"orgId,omitempty"`
	// The last updated timestamp of the ResourceOwner
	Updated time.Time `json:"updated,omitempty"`
}