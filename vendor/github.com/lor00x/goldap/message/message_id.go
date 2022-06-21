package message

import "fmt"

func readTaggedMessageID(bytes *Bytes, class int, tag int) (ret MessageID, err error) {
	var integer INTEGER
	integer, err = readTaggedPositiveINTEGER(bytes, class, tag)
	if err != nil {
		err = LdapError{fmt.Sprintf("readTaggedMessageID:\n%s", err.Error())}
		return
	}
	return MessageID(integer), err
}

//        MessageID ::= INTEGER (0 ..  maxInt)
//
//        maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --
//
func readMessageID(bytes *Bytes) (ret MessageID, err error) {
	return readTaggedMessageID(bytes, classUniversal, tagInteger)
}

//        MessageID ::= INTEGER (0 ..  maxInt)
//
//        maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --
//
func (m MessageID) write(bytes *Bytes) int {
	return INTEGER(m).write(bytes)
}
func (m MessageID) writeTagged(bytes *Bytes, class int, tag int) int {
	return INTEGER(m).writeTagged(bytes, class, tag)
}

//        MessageID ::= INTEGER (0 ..  maxInt)
//
//        maxInt INTEGER ::= 2147483647 -- (2^^31 - 1) --
//
func (m MessageID) size() int {
	return INTEGER(m).size()
}
func (m MessageID) sizeTagged(tag int) int {
	return INTEGER(m).sizeTagged(tag)
}
func (l MessageID) Int() int {
	return int(l)
}
