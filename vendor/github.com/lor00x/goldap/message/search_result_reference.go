package message

import "fmt"

//
//        SearchResultReference ::= [APPLICATION 19] SEQUENCE
//                                  SIZE (1..MAX) OF uri URI
func readSearchResultReference(bytes *Bytes) (ret SearchResultReference, err error) {
	err = bytes.ReadSubBytes(classApplication, TagSearchResultReference, ret.readComponents)
	if err != nil {
		err = LdapError{fmt.Sprintf("readSearchResultReference:\n%s", err.Error())}
		return
	}
	return
}
func (s *SearchResultReference) readComponents(bytes *Bytes) (err error) {
	for bytes.HasMoreData() {
		var uri URI
		uri, err = readURI(bytes)
		if err != nil {
			err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
			return
		}
		*s = append(*s, uri)
	}
	if len(*s) == 0 {
		err = LdapError{"readComponents: expecting at least one URI"}
		return
	}
	return
}

//
//        SearchResultReference ::= [APPLICATION 19] SEQUENCE
//                                  SIZE (1..MAX) OF uri URI
func (s SearchResultReference) write(bytes *Bytes) (size int) {
	for i := len(s) - 1; i >= 0; i-- {
		size += s[i].write(bytes)
	}
	size += bytes.WriteTagAndLength(classApplication, isCompound, TagSearchResultReference, size)
	return
}

//
//        SearchResultReference ::= [APPLICATION 19] SEQUENCE
//                                  SIZE (1..MAX) OF uri URI
func (s SearchResultReference) size() (size int) {
	for _, uri := range s {
		size += uri.size()
	}
	size += sizeTagAndLength(tagSequence, size)
	return
}
