package message

import "fmt"

//
//        PartialAttribute ::= SEQUENCE {
//             type       AttributeDescription,
//             vals       SET OF value AttributeValue }
func readPartialAttribute(bytes *Bytes) (ret PartialAttribute, err error) {
	ret = PartialAttribute{vals: make([]AttributeValue, 0, 10)}
	err = bytes.ReadSubBytes(classUniversal, tagSequence, ret.readComponents)
	if err != nil {
		err = LdapError{fmt.Sprintf("readPartialAttribute:\n%s", err.Error())}
		return
	}
	return
}
func (partialattribute *PartialAttribute) readComponents(bytes *Bytes) (err error) {
	partialattribute.type_, err = readAttributeDescription(bytes)
	if err != nil {
		err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
		return
	}
	err = bytes.ReadSubBytes(classUniversal, tagSet, partialattribute.readValsComponents)
	if err != nil {
		err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
		return
	}
	return
}
func (partialattribute *PartialAttribute) readValsComponents(bytes *Bytes) (err error) {
	for bytes.HasMoreData() {
		var attributevalue AttributeValue
		attributevalue, err = readAttributeValue(bytes)
		if err != nil {
			err = LdapError{fmt.Sprintf("readValsComponents:\n%s", err.Error())}
			return
		}
		partialattribute.vals = append(partialattribute.vals, attributevalue)
	}
	return
}

//
//        PartialAttribute ::= SEQUENCE {
//             type       AttributeDescription,
//             vals       SET OF value AttributeValue }
func (p PartialAttribute) write(bytes *Bytes) (size int) {
	for i := len(p.vals) - 1; i >= 0; i-- {
		size += p.vals[i].write(bytes)
	}
	size += bytes.WriteTagAndLength(classUniversal, isCompound, tagSet, size)
	size += p.type_.write(bytes)
	size += bytes.WriteTagAndLength(classUniversal, isCompound, tagSequence, size)
	return
}

//
//        PartialAttribute ::= SEQUENCE {
//             type       AttributeDescription,
//             vals       SET OF value AttributeValue }
func (p PartialAttribute) size() (size int) {
	for _, value := range p.vals {
		size += value.size()
	}
	size += sizeTagAndLength(tagSet, size)
	size += p.type_.size()
	size += sizeTagAndLength(tagSequence, size)
	return
}
func (p *PartialAttribute) Type_() AttributeDescription {
	return p.type_
}
func (p *PartialAttribute) Vals() []AttributeValue {
	return p.vals
}
