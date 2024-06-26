/*
 * Configuration API.
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package corecfgclient

// The credential format for a cloud account
type CloudAccountAwsCredential struct {
	Arn         string `json:"arn,omitempty"`
	ExternalId  string `json:"externalId,omitempty"`
	IamType     string `json:"iamType,omitempty"`
	Region      string `json:"region,omitempty"`
	SessionName string `json:"sessionName,omitempty"`
}
