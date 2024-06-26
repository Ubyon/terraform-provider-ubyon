/*
 * Configuration API.
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package corecfgclient

// CompositeError represents the error details of composite api with the code, message, causes and a referenceId of each request
type CompositeError struct {
	// Al list of all errors specific to this referenceId
	Errors []ErrorResponse `json:"errors,omitempty"`
	// A referenceId used to refer this specific error to the request
	ReferenceId string `json:"referenceId,omitempty"`
}
