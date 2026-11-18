package giop

// ServiceContextList
// IIOP ServiceContextList
type ServiceContextList struct {
	SequenceLength []byte            // 4
	ServiceContext []*ServiceContext // SequenceLength
}

// ServiceContext
// IIOP ServiceContext
type ServiceContext struct {
	VSCID           []byte // 3
	SCID            []byte // 1
	_sequenceLength []byte // 4
	Endianness      []byte // 1
	Data            []byte // _sequenceLength-1
}

// contextDataLength returns the CDR encoded length of context_data (Endianness + Data).
func (sc *ServiceContext) contextDataLength() int {
	return 1 + len(sc.Data)
}

// encodedSize returns the total bytes of one ServiceContext:
// VSCID(3) + SCID(1) + length(4) + context_data.
// WebLogic's IIOP decoder reads the list sequentially and does not require
// 4-byte alignment padding between contexts, so none is emitted.
func (sc *ServiceContext) encodedSize() int {
	return 3 + 1 + 4 + sc.contextDataLength()
}
