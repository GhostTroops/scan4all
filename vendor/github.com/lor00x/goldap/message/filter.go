package message

import "fmt"

//
//        Filter ::= CHOICE {
//             and             [0] SET SIZE (1..MAX) OF filter Filter,
//             or              [1] SET SIZE (1..MAX) OF filter Filter,
//             not             [2] Filter,
//             equalityMatch   [3] AttributeValueAssertion,
//
//
//
//Sermersheim                 Standards Track                    [Page 57]
//
//
//RFC 4511                         LDAPv3                        June 2006
//
//
//             substrings      [4] SubstringFilter,
//             greaterOrEqual  [5] AttributeValueAssertion,
//             lessOrEqual     [6] AttributeValueAssertion,
//             present         [7] AttributeDescription,
//             approxMatch     [8] AttributeValueAssertion,
//             extensibleMatch [9] MatchingRuleAssertion,
//             ...  }

func readFilter(bytes *Bytes) (filter Filter, err error) {
	var tagAndLength TagAndLength
	tagAndLength, err = bytes.PreviewTagAndLength()
	if err != nil {
		err = LdapError{fmt.Sprintf("readFilter:\n%s", err.Error())}
		return
	}
	err = tagAndLength.ExpectClass(classContextSpecific)
	if err != nil {
		err = LdapError{fmt.Sprintf("readFilter:\n%s", err.Error())}
		return
	}
	switch tagAndLength.Tag {
	case TagFilterAnd:
		filter, err = readFilterAnd(bytes)
	case TagFilterOr:
		filter, err = readFilterOr(bytes)
	case TagFilterNot:
		filter, err = readFilterNot(bytes)
	case TagFilterEqualityMatch:
		filter, err = readFilterEqualityMatch(bytes)
	case TagFilterSubstrings:
		filter, err = readFilterSubstrings(bytes)
	case TagFilterGreaterOrEqual:
		filter, err = readFilterGreaterOrEqual(bytes)
	case TagFilterLessOrEqual:
		filter, err = readFilterLessOrEqual(bytes)
	case TagFilterPresent:
		filter, err = readFilterPresent(bytes)
	case TagFilterApproxMatch:
		filter, err = readFilterApproxMatch(bytes)
	case TagFilterExtensibleMatch:
		filter, err = readFilterExtensibleMatch(bytes)
	default:
		err = LdapError{fmt.Sprintf("readFilter: invalid tag value %d for filter", tagAndLength.Tag)}
		return
	}
	if err != nil {
		err = LdapError{fmt.Sprintf("readFilter:\n%s", err.Error())}
		return
	}
	return
}
