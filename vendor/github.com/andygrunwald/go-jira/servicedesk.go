package jira

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"

	"github.com/google/go-querystring/query"
)

// ServiceDeskService handles ServiceDesk for the Jira instance / API.
type ServiceDeskService struct {
	client *Client
}

// ServiceDeskOrganizationDTO is a DTO for ServiceDesk organizations
type ServiceDeskOrganizationDTO struct {
	OrganizationID int `json:"organizationId,omitempty" structs:"organizationId,omitempty"`
}

// GetOrganizationsWithContext returns a list of
// all organizations associated with a service desk.
//
// https://developer.atlassian.com/cloud/jira/service-desk/rest/api-group-organization/#api-rest-servicedeskapi-servicedesk-servicedeskid-organization-get
func (s *ServiceDeskService) GetOrganizationsWithContext(ctx context.Context, serviceDeskID interface{}, start int, limit int, accountID string) (*PagedDTO, *Response, error) {
	apiEndPoint := fmt.Sprintf("rest/servicedeskapi/servicedesk/%v/organization?start=%d&limit=%d", serviceDeskID, start, limit)
	if accountID != "" {
		apiEndPoint += fmt.Sprintf("&accountId=%s", accountID)
	}

	req, err := s.client.NewRequestWithContext(ctx, "GET", apiEndPoint, nil)
	req.Header.Set("Accept", "application/json")

	if err != nil {
		return nil, nil, err
	}

	orgs := new(PagedDTO)
	resp, err := s.client.Do(req, &orgs)
	if err != nil {
		jerr := NewJiraError(resp, err)
		return nil, resp, jerr
	}

	return orgs, resp, nil
}

// GetOrganizations wraps GetOrganizationsWithContext using the background context.
func (s *ServiceDeskService) GetOrganizations(serviceDeskID interface{}, start int, limit int, accountID string) (*PagedDTO, *Response, error) {
	return s.GetOrganizationsWithContext(context.Background(), serviceDeskID, start, limit, accountID)
}

// AddOrganizationWithContext adds an organization to
// a service desk. If the organization ID is already
// associated with the service desk, no change is made
// and the resource returns a 204 success code.
//
// https://developer.atlassian.com/cloud/jira/service-desk/rest/api-group-organization/#api-rest-servicedeskapi-servicedesk-servicedeskid-organization-post
// Caller must close resp.Body
func (s *ServiceDeskService) AddOrganizationWithContext(ctx context.Context, serviceDeskID interface{}, organizationID int) (*Response, error) {
	apiEndPoint := fmt.Sprintf("rest/servicedeskapi/servicedesk/%v/organization", serviceDeskID)

	organization := ServiceDeskOrganizationDTO{
		OrganizationID: organizationID,
	}

	req, err := s.client.NewRequestWithContext(ctx, "POST", apiEndPoint, organization)

	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req, nil)
	if err != nil {
		jerr := NewJiraError(resp, err)
		return resp, jerr
	}

	return resp, nil
}

// AddOrganization wraps AddOrganizationWithContext using the background context.
// Caller must close resp.Body
func (s *ServiceDeskService) AddOrganization(serviceDeskID interface{}, organizationID int) (*Response, error) {
	return s.AddOrganizationWithContext(context.Background(), serviceDeskID, organizationID)
}

// RemoveOrganizationWithContext removes an organization
// from a service desk. If the organization ID does not
// match an organization associated with the service desk,
// no change is made and the resource returns a 204 success code.
//
// https://developer.atlassian.com/cloud/jira/service-desk/rest/api-group-organization/#api-rest-servicedeskapi-servicedesk-servicedeskid-organization-delete
// Caller must close resp.Body
func (s *ServiceDeskService) RemoveOrganizationWithContext(ctx context.Context, serviceDeskID interface{}, organizationID int) (*Response, error) {
	apiEndPoint := fmt.Sprintf("rest/servicedeskapi/servicedesk/%v/organization", serviceDeskID)

	organization := ServiceDeskOrganizationDTO{
		OrganizationID: organizationID,
	}

	req, err := s.client.NewRequestWithContext(ctx, "DELETE", apiEndPoint, organization)

	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req, nil)
	if err != nil {
		jerr := NewJiraError(resp, err)
		return resp, jerr
	}

	return resp, nil
}

// RemoveOrganization wraps RemoveOrganizationWithContext using the background context.
// Caller must close resp.Body
func (s *ServiceDeskService) RemoveOrganization(serviceDeskID interface{}, organizationID int) (*Response, error) {
	return s.RemoveOrganizationWithContext(context.Background(), serviceDeskID, organizationID)
}

// AddCustomersWithContext adds customers to the given service desk.
//
// https://developer.atlassian.com/cloud/jira/service-desk/rest/api-group-servicedesk/#api-rest-servicedeskapi-servicedesk-servicedeskid-customer-post
func (s *ServiceDeskService) AddCustomersWithContext(ctx context.Context, serviceDeskID interface{}, acountIDs ...string) (*Response, error) {
	apiEndpoint := fmt.Sprintf("rest/servicedeskapi/servicedesk/%v/customer", serviceDeskID)

	payload := struct {
		AccountIDs []string `json:"accountIds"`
	}{
		AccountIDs: acountIDs,
	}
	req, err := s.client.NewRequestWithContext(ctx, "POST", apiEndpoint, payload)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req, nil)
	if err != nil {
		return resp, NewJiraError(resp, err)
	}

	defer resp.Body.Close()
	_, _ = io.Copy(ioutil.Discard, resp.Body)

	return resp, nil
}

// AddCustomers wraps AddCustomersWithContext using the background context.
func (s *ServiceDeskService) AddCustomers(serviceDeskID interface{}, acountIDs ...string) (*Response, error) {
	return s.AddCustomersWithContext(context.Background(), serviceDeskID, acountIDs...)
}

// RemoveCustomersWithContext removes customers to the given service desk.
//
// https://developer.atlassian.com/cloud/jira/service-desk/rest/api-group-servicedesk/#api-rest-servicedeskapi-servicedesk-servicedeskid-customer-delete
func (s *ServiceDeskService) RemoveCustomersWithContext(ctx context.Context, serviceDeskID interface{}, acountIDs ...string) (*Response, error) {
	apiEndpoint := fmt.Sprintf("rest/servicedeskapi/servicedesk/%v/customer", serviceDeskID)

	payload := struct {
		AccountIDs []string `json:"accountIDs"`
	}{
		AccountIDs: acountIDs,
	}
	req, err := s.client.NewRequestWithContext(ctx, "DELETE", apiEndpoint, payload)
	if err != nil {
		return nil, err
	}

	resp, err := s.client.Do(req, nil)
	if err != nil {
		return resp, NewJiraError(resp, err)
	}

	defer resp.Body.Close()
	_, _ = io.Copy(ioutil.Discard, resp.Body)

	return resp, nil
}

// RemoveCustomers wraps RemoveCustomersWithContext using the background context.
func (s *ServiceDeskService) RemoveCustomers(serviceDeskID interface{}, acountIDs ...string) (*Response, error) {
	return s.RemoveCustomersWithContext(context.Background(), serviceDeskID, acountIDs...)
}

// ListCustomersWithContext lists customers for a ServiceDesk.
//
// https://developer.atlassian.com/cloud/jira/service-desk/rest/api-group-servicedesk/#api-rest-servicedeskapi-servicedesk-servicedeskid-customer-get
func (s *ServiceDeskService) ListCustomersWithContext(ctx context.Context, serviceDeskID interface{}, options *CustomerListOptions) (*CustomerList, *Response, error) {
	apiEndpoint := fmt.Sprintf("rest/servicedeskapi/servicedesk/%v/customer", serviceDeskID)
	req, err := s.client.NewRequestWithContext(ctx, "GET", apiEndpoint, nil)
	if err != nil {
		return nil, nil, err
	}

	// this is an experiemntal endpoint
	req.Header.Set("X-ExperimentalApi", "opt-in")

	if options != nil {
		q, err := query.Values(options)
		if err != nil {
			return nil, nil, err
		}
		req.URL.RawQuery = q.Encode()
	}

	resp, err := s.client.Do(req, nil)
	if err != nil {
		return nil, resp, NewJiraError(resp, err)
	}
	defer resp.Body.Close()

	customerList := new(CustomerList)
	if err := json.NewDecoder(resp.Body).Decode(customerList); err != nil {
		return nil, resp, fmt.Errorf("could not unmarshall the data into struct")
	}

	return customerList, resp, nil
}

// ListCustomers wraps ListCustomersWithContext using the background context.
func (s *ServiceDeskService) ListCustomers(serviceDeskID interface{}, options *CustomerListOptions) (*CustomerList, *Response, error) {
	return s.ListCustomersWithContext(context.Background(), serviceDeskID, options)
}
