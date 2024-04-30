/*
 * Configuration API.
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package corecfgclient

import "encoding/json"

type CredentialType string

const (
	CredentialJwt      CredentialType = "JWT"
	CredentialApiKey   CredentialType = "APIKEY"
	CredentialUserPswd CredentialType = "USERPSWD"
	CredentialCert     CredentialType = "CERT"
)

// AppSecretsStoreAttributes represents the format of attributes for App-SecretsStore association
type AppSecretsStoreAttributes struct {
	Attributes IsCredentialAttributes `json:"attributes,omitempty"`
	// The credentials of the app-secretsstore association JWT CredentialJwt APIKEY CredentialApiKey USERPSWD CredentialUserPswd CERT CredentialCert
	CredentialType CredentialType `json:"credentialType,omitempty"`
	// The scope of secret store usage by the principals USER SSAPrincipalUser WORKLOAD SSAPrincipalWorkload USER_WORKLOAD SSAPrincipalUserWorkload
	PrincipalScope string `json:"principalScope,omitempty"`
}

func (ss *AppSecretsStoreAttributes) UnmarshalJSON(bs []byte) error {
	var tss map[string]interface{}
	err := json.Unmarshal(bs, &tss)
	if err != nil {
		return err
	}
	attributes := tss["attributes"].(*AppSecretsStoreAttributes)

	type appSecretsStoreAttributes AppSecretsStoreAttributes
	fss := (*appSecretsStoreAttributes)(ss)
	switch attributes.CredentialType {
	case CredentialApiKey:
		fss.Attributes = &ApiKeyAttributes{}
	case CredentialJwt:
		fss.Attributes = &JwtAttributes{}
	case CredentialUserPswd:
		fss.Attributes = &UserPswdAttributes{}
	case CredentialCert:
		fss.Attributes = &AppSecretsStoreCertAttributes{}
	default:
		fss.Attributes = &DefaultCredentialsAttributes{}
	}

	err = json.Unmarshal(bs, &fss)
	if err != nil {
		return err
	}
	return nil
}
