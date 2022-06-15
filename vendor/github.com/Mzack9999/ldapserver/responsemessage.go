package ldapserver

import ldap "github.com/lor00x/goldap/message"

func NewBindResponse(resultCode int) ldap.BindResponse {
	r := ldap.BindResponse{}
	r.SetResultCode(resultCode)
	return r
}

func NewResponse(resultCode int) ldap.LDAPResult {
	r := ldap.LDAPResult{}
	r.SetResultCode(resultCode)
	return r
}

func NewExtendedResponse(resultCode int) ldap.ExtendedResponse {
	r := ldap.ExtendedResponse{}
	r.SetResultCode(resultCode)
	return r
}

func NewCompareResponse(resultCode int) ldap.CompareResponse {
	r := ldap.CompareResponse{}
	r.SetResultCode(resultCode)
	return r
}

func NewModifyResponse(resultCode int) ldap.ModifyResponse {
	r := ldap.ModifyResponse{}
	r.SetResultCode(resultCode)
	return r
}

func NewDeleteResponse(resultCode int) ldap.DelResponse {
	r := ldap.DelResponse{}
	r.SetResultCode(resultCode)
	return r
}

func NewAddResponse(resultCode int) ldap.AddResponse {
	r := ldap.AddResponse{}
	r.SetResultCode(resultCode)
	return r
}

func NewSearchResultDoneResponse(resultCode int) ldap.SearchResultDone {
	r := ldap.SearchResultDone{}
	r.SetResultCode(resultCode)
	return r
}

func NewSearchResultEntry(objectname string) ldap.SearchResultEntry {
	r := ldap.SearchResultEntry{}
	r.SetObjectName(objectname)
	return r
}
