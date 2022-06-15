package message

import "fmt"

//
//        AttributeList ::= SEQUENCE OF attribute Attribute

func readAttributeList(bytes *Bytes) (ret AttributeList, err error) {
	err = bytes.ReadSubBytes(classUniversal, tagSequence, ret.readComponents)
	if err != nil {
		err = LdapError{fmt.Sprintf("readAttributeList:\n%s", err.Error())}
		return
	}
	return
}
func (list *AttributeList) readComponents(bytes *Bytes) (err error) {
	for bytes.HasMoreData() {
		var attr Attribute
		attr, err = readAttribute(bytes)
		if err != nil {
			err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
			return
		}
		*list = append(*list, attr)
	}
	return
}

func (list AttributeList) size() (size int) {
	for _, att := range list {
		size += att.size()
	}
	size += sizeTagAndLength(tagSequence, size)
	return
}

func (list AttributeList) write(bytes *Bytes) (size int) {
	for i := len(list) - 1; i >= 0; i-- {
		size += list[i].write(bytes)
	}
	size += bytes.WriteTagAndLength(classUniversal, isCompound, tagSequence, size)
	return
}
