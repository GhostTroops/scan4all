package message

import "fmt"

//             substrings      [4] SubstringFilter,
func readFilterSubstrings(bytes *Bytes) (filtersubstrings FilterSubstrings, err error) {
	var substringfilter SubstringFilter
	substringfilter, err = readTaggedSubstringFilter(bytes, classContextSpecific, TagFilterSubstrings)
	if err != nil {
		err = LdapError{fmt.Sprintf("readFilterSubstrings:\n%s", err.Error())}
		return
	}
	filtersubstrings = FilterSubstrings(substringfilter)
	return
}

//
//        SubstringFilter ::= SEQUENCE {
//             type           AttributeDescription,
//             substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
//                  initial [0] AssertionValue,  -- can occur at most once
//                  any     [1] AssertionValue,
//                  final   [2] AssertionValue } -- can occur at most once
//             }
func readTaggedSubstringFilter(bytes *Bytes, class int, tag int) (substringfilter SubstringFilter, err error) {
	err = bytes.ReadSubBytes(class, tag, substringfilter.readComponents)
	if err != nil {
		err = LdapError{fmt.Sprintf("readTaggedSubstringFilter:\n%s", err.Error())}
		return
	}
	return
}
func (substringfilter *SubstringFilter) readComponents(bytes *Bytes) (err error) {
	substringfilter.type_, err = readAttributeDescription(bytes)
	if err != nil {
		err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
		return
	}
	err = substringfilter.readSubstrings(bytes)
	if err != nil {
		err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
		return
	}
	return
}
func (substringfilter *SubstringFilter) readSubstrings(bytes *Bytes) (err error) {
	err = bytes.ReadSubBytes(classUniversal, tagSequence, substringfilter.readSubstringsComponents)
	if err != nil {
		err = LdapError{fmt.Sprintf("readSubstrings:\n%s", err.Error())}
		return
	}
	return
}
func (substringfilter *SubstringFilter) readSubstringsComponents(bytes *Bytes) (err error) {
	var foundInitial = 0
	var foundFinal = 0
	var tagAndLength TagAndLength
	for bytes.HasMoreData() {
		tagAndLength, err = bytes.PreviewTagAndLength()
		if err != nil {
			err = LdapError{fmt.Sprintf("readSubstringsComponents:\n%s", err.Error())}
			return
		}
		var assertionvalue AssertionValue
		switch tagAndLength.Tag {
		case TagSubstringInitial:
			foundInitial++
			if foundInitial > 1 {
				err = LdapError{"readSubstringsComponents: initial can occur at most once"}
				return
			}
			assertionvalue, err = readTaggedAssertionValue(bytes, classContextSpecific, TagSubstringInitial)
			if err != nil {
				err = LdapError{fmt.Sprintf("readSubstringsComponents:\n%s", err.Error())}
				return
			}
			substringfilter.substrings = append(substringfilter.substrings, SubstringInitial(assertionvalue))
		case TagSubstringAny:
			assertionvalue, err = readTaggedAssertionValue(bytes, classContextSpecific, TagSubstringAny)
			if err != nil {
				err = LdapError{fmt.Sprintf("readSubstringsComponents:\n%s", err.Error())}
				return
			}
			substringfilter.substrings = append(substringfilter.substrings, SubstringAny(assertionvalue))
		case TagSubstringFinal:
			foundFinal++
			if foundFinal > 1 {
				err = LdapError{"readSubstringsComponents: final can occur at most once"}
				return
			}
			assertionvalue, err = readTaggedAssertionValue(bytes, classContextSpecific, TagSubstringFinal)
			if err != nil {
				err = LdapError{fmt.Sprintf("readSubstringsComponents:\n%s", err.Error())}
				return
			}
			substringfilter.substrings = append(substringfilter.substrings, SubstringFinal(assertionvalue))
		default:
			err = LdapError{fmt.Sprintf("readSubstringsComponents: invalid tag %d", tagAndLength.Tag)}
			return
		}
	}
	if len(substringfilter.substrings) == 0 {
		err = LdapError{"readSubstringsComponents: expecting at least one substring"}
		return
	}
	return
}

//             substrings      [4] SubstringFilter,
func (f FilterSubstrings) write(bytes *Bytes) int {
	return SubstringFilter(f).writeTagged(bytes, classContextSpecific, TagFilterSubstrings)
}
func (s SubstringFilter) writeTagged(bytes *Bytes, class int, tag int) (size int) {
	for i := len(s.substrings) - 1; i >= 0; i-- {
		substring := s.substrings[i]
		switch substring.(type) {
		case SubstringInitial:
			size += AssertionValue(substring.(SubstringInitial)).writeTagged(bytes, classContextSpecific, TagSubstringInitial)
		case SubstringAny:
			size += AssertionValue(substring.(SubstringAny)).writeTagged(bytes, classContextSpecific, TagSubstringAny)
		case SubstringFinal:
			size += AssertionValue(substring.(SubstringFinal)).writeTagged(bytes, classContextSpecific, TagSubstringFinal)
		default:
			panic("Unknown type for SubstringFilter substring")
		}
	}
	size += bytes.WriteTagAndLength(classUniversal, isCompound, tagSequence, size)
	size += s.type_.write(bytes)
	size += bytes.WriteTagAndLength(class, isCompound, tag, size)
	return
}

//
//        SubstringFilter ::= SEQUENCE {
//             type           AttributeDescription,
//             substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
//                  initial [0] AssertionValue,  -- can occur at most once
//                  any     [1] AssertionValue,
//                  final   [2] AssertionValue } -- can occur at most once
//             }
func (s SubstringFilter) write(bytes *Bytes) (size int) {
	return s.writeTagged(bytes, classUniversal, tagSequence)
}
func (filter FilterSubstrings) getFilterTag() int {
	return TagFilterSubstrings
}

//             substrings      [4] SubstringFilter,
func (f FilterSubstrings) size() int {
	return SubstringFilter(f).sizeTagged(TagFilterSubstrings)
}

//
//        SubstringFilter ::= SEQUENCE {
//             type           AttributeDescription,
//             substrings     SEQUENCE SIZE (1..MAX) OF substring CHOICE {
//                  initial [0] AssertionValue,  -- can occur at most once
//                  any     [1] AssertionValue,
//                  final   [2] AssertionValue } -- can occur at most once
//             }
func (s SubstringFilter) size() (size int) {
	return s.sizeTagged(tagSequence)
}
func (s SubstringFilter) sizeTagged(tag int) (size int) {
	for _, substring := range s.substrings {
		switch substring.(type) {
		case SubstringInitial:
			size += AssertionValue(substring.(SubstringInitial)).sizeTagged(TagSubstringInitial)
		case SubstringAny:
			size += AssertionValue(substring.(SubstringAny)).sizeTagged(TagSubstringAny)
		case SubstringFinal:
			size += AssertionValue(substring.(SubstringFinal)).sizeTagged(TagSubstringFinal)
		default:
			panic("Unknown type for SubstringFilter substring")
		}
	}
	size += sizeTagAndLength(tagSequence, size)
	size += s.type_.size()
	size += sizeTagAndLength(tag, size)
	return
}
func (s *FilterSubstrings) Type_() AttributeDescription {
	return s.type_
}
func (s *FilterSubstrings) Substrings() []Substring {
	return s.substrings
}
