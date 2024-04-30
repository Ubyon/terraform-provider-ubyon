/*
 * Configuration API.
 *
 * No description provided (generated by Swagger Codegen https://github.com/swagger-api/swagger-codegen)
 *
 * API version: 1.0.0
 * Generated by: Swagger Codegen (https://github.com/swagger-api/swagger-codegen.git)
 */
package corecfgclient

// CompositeError represents the list of error details of all the requests of a composite api
type CompositeErrors struct {
	// A list of all errors of the composite api request
	CompositeErrors []CompositeError `json:"compositeErrors,omitempty"`
}