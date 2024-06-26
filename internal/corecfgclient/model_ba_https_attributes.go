/*
 * Configuration API.
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package corecfgclient

// BAHttpsAttributes represents the https attributes required for browser access
type BaHttpsAttributes struct {
	Headers map[string][]string `json:"headers,omitempty"`
	// The Uri to redirect the users after entering the application. Defaults to \"/\"
	StartUri string `json:"startUri,omitempty"`
}
