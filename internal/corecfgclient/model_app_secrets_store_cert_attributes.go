/*
 * Configuration API.
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package corecfgclient

// AppSecretsStoreCertAttributes represents the format of credential certkey attributes for App-SecretsStore association
type AppSecretsStoreCertAttributes struct {
	CaCertPath     string `json:"caCertPath,omitempty"`
	PrivateKeyPath string `json:"privateKeyPath"`
	PublicKeyPath  string `json:"publicKeyPath"`
}
