package message

import "fmt"

//             and             [0] SET SIZE (1..MAX) OF filter Filter,

func (filterAnd FilterAnd) getFilterTag() int {
	return TagFilterAnd
}

func (filterAnd FilterAnd) size() (size int) {
	for _, filter := range filterAnd {
		size += filter.size()
	}
	size += sizeTagAndLength(TagFilterAnd, size)
	return
}

func (filterAnd *FilterAnd) readComponents(bytes *Bytes) (err error) {
	count := 0
	for bytes.HasMoreData() {
		count++
		var filter Filter
		filter, err = readFilter(bytes)
		if err != nil {
			err = LdapError{fmt.Sprintf("readComponents (filter %d):\n%s", count, err.Error())}
			return
		}
		*filterAnd = append(*filterAnd, filter)
	}
	if len(*filterAnd) == 0 {
		err = LdapError{"readComponents: expecting at least one Filter"}
		return
	}
	return
}

func (filterAnd FilterAnd) write(bytes *Bytes) (size int) {

	for i := len(filterAnd) - 1; i >= 0; i-- {
		size += filterAnd[i].write(bytes)
	}
	size += bytes.WriteTagAndLength(classContextSpecific, isCompound, TagFilterAnd, size)
	return
}

func readFilterAnd(bytes *Bytes) (filterand FilterAnd, err error) {
	err = bytes.ReadSubBytes(classContextSpecific, TagFilterAnd, filterand.readComponents)
	if err != nil {
		err = LdapError{fmt.Sprintf("readFilterAnd:\n%s", err.Error())}
		return
	}
	return
}
