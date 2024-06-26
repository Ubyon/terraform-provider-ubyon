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

// AppConnector represents the response format of app connector details
type AppConnector struct {
	// The creation timestamp of the app connector
	Created time.Time `json:"created,omitempty"`
	// The Id of the app connector
	Id string `json:"id"`
	// The Internal Id of the app connector is being added
	InternalId string `json:"internalId,omitempty"`
	// The name of the app connector
	Name string `json:"name"`
	// The Id of the org associated with the app connector
	OrgId string `json:"orgId,omitempty"`
	// The type of the appconnector EXG AppConnectorTypeExg ULINK AppConnectorTypeUlink
	Type_ string `json:"type,omitempty"`
	// The last updated timestamp of the app connector
	Updated time.Time `json:"updated,omitempty"`
	// The Id of the user by whom the org was last updated
	WhoUpdated string `json:"whoUpdated,omitempty"`
}
