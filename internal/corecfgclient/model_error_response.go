/*
 * Configuration API.
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package corecfgclient

// APiError represents the error details with the code, message and causes
type ErrorResponse struct {
	// The list of error causes which is a non empty list for error responses
	ErrorCauses map[string][]string `json:"errorCauses,omitempty"`
	// Integer which is a non zero value for error responses
	ErrorCode int64 `json:"errorCode,omitempty"`
	// A message which is a non empty string for error responses
	ErrorMessage string `json:"errorMessage,omitempty"`
}
