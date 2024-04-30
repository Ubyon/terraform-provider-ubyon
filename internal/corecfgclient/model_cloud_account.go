/*
 * Configuration API.
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package corecfgclient

// CloudAccount represents the response format of Cloud Account
type CloudAccount struct {
	// The ID of the Cloud Account
	AccountId string `json:"accountId"`
	// The name of the scloud account, must be unique in the org
	AccountName    string                     `json:"accountName"`
	AwsCredentials *CloudAccountAwsCredential `json:"awsCredentials,omitempty"`
	// The description for the cloud account
	Description string `json:"description,omitempty"`
	// The operation status of the cloud account
	OperStatus   string `json:"operStatus,omitempty"`
	ProviderName string `json:"providerName,omitempty"`
}