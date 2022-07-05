package message

import "fmt"

//
//        PartialAttributeList ::= SEQUENCE OF
//                             partialAttribute PartialAttribute
func readPartialAttributeList(bytes *Bytes) (ret PartialAttributeList, err error) {
	ret = PartialAttributeList(make([]PartialAttribute, 0, 10))
	err = bytes.ReadSubBytes(classUniversal, tagSequence, ret.readComponents)
	if err != nil {
		err = LdapError{fmt.Sprintf("readPartialAttributeList:\n%s", err.Error())}
		return
	}
	return
}
func (partialattributelist *PartialAttributeList) readComponents(bytes *Bytes) (err error) {
	for bytes.HasMoreData() {
		var partialattribute PartialAttribute
		partialattribute, err = readPartialAttribute(bytes)
		if err != nil {
			err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
			return
		}
		*partialattributelist = append(*partialattributelist, partialattribute)
	}
	return
}

//
//        PartialAttributeList ::= SEQUENCE OF
//                             partialAttribute PartialAttribute
func (p PartialAttributeList) write(bytes *Bytes) (size int) {
	for i := len(p) - 1; i >= 0; i-- {
		size += p[i].write(bytes)
	}
	size += bytes.WriteTagAndLength(classUniversal, isCompound, tagSequence, size)
	return
}

//
//        PartialAttributeList ::= SEQUENCE OF
//                             partialAttribute PartialAttribute
func (p PartialAttributeList) size() (size int) {
	for _, att := range p {
		size += att.size()
	}
	size += sizeTagAndLength(tagSequence, size)
	return
}
func (p *PartialAttributeList) add(a PartialAttribute) {
	*p = append(*p, a)
}
