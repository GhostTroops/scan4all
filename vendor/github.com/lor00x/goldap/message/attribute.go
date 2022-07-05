package message

import "fmt"

//
//        Attribute ::= PartialAttribute(WITH COMPONENTS {
//             ...,
//             vals (SIZE(1..MAX))})

func (attribute *Attribute) Type_() AttributeDescription {
	return attribute.type_
}

func (attribute *Attribute) Vals() []AttributeValue {
	return attribute.vals
}

func readAttribute(bytes *Bytes) (ret Attribute, err error) {
	var par PartialAttribute
	par, err = readPartialAttribute(bytes)
	if err != nil {
		err = LdapError{fmt.Sprintf("readAttribute:\n%s", err.Error())}
		return
	}
	if len(par.vals) == 0 {
		err = LdapError{"readAttribute: expecting at least one value"}
		return
	}
	ret = Attribute(par)
	return

}

func (attribute Attribute) size() (size int) {
	return PartialAttribute(attribute).size()
}

func (attribute Attribute) write(bytes *Bytes) (size int) {
	return PartialAttribute(attribute).write(bytes)
}
