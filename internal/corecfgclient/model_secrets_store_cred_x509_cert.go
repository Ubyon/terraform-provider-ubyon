/*
 * Configuration API.
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package corecfgclient

// SecretsStoreCredX509Cert represents the Secrets Store Credential of type Certificate
type SecretsStoreCredX509Cert struct {
	PublicKeyPath  string `json:"publicKeyPath,omitempty"`
	SecretsStoreId string `json:"secretsStoreId,omitempty"`
}
