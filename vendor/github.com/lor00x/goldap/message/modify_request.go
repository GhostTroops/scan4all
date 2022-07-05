package message

import "fmt"

//
//        ModifyRequest ::= [APPLICATION 6] SEQUENCE {
//             object          LDAPDN,
//             changes         SEQUENCE OF change SEQUENCE {
//                  operation       ENUMERATED {
//                       add     (0),
//                       delete  (1),
//                       replace (2),
//                       ...  },
//                  modification    PartialAttribute } }
func readModifyRequest(bytes *Bytes) (ret ModifyRequest, err error) {
	err = bytes.ReadSubBytes(classApplication, TagModifyRequest, ret.readComponents)
	if err != nil {
		err = LdapError{fmt.Sprintf("readModifyRequest:\n%s", err.Error())}
		return
	}
	return
}
func (m *ModifyRequest) readComponents(bytes *Bytes) (err error) {
	m.object, err = readLDAPDN(bytes)
	if err != nil {
		err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
		return
	}
	err = bytes.ReadSubBytes(classUniversal, tagSequence, m.readChanges)
	return
}
func (m *ModifyRequest) readChanges(bytes *Bytes) (err error) {
	for bytes.HasMoreData() {
		var c ModifyRequestChange
		c, err = readModifyRequestChange(bytes)
		if err != nil {
			err = LdapError{fmt.Sprintf("readChanges:\n%s", err.Error())}
			return
		}
		m.changes = append(m.changes, c)
	}
	return
}

//
//        ModifyRequest ::= [APPLICATION 6] SEQUENCE {
//             object          LDAPDN,
//             changes         SEQUENCE OF change SEQUENCE {
//                  operation       ENUMERATED {
//                       add     (0),
//                       delete  (1),
//                       replace (2),
//                       ...  },
//                  modification    PartialAttribute } }
func (m ModifyRequest) write(bytes *Bytes) (size int) {
	for i := len(m.changes) - 1; i >= 0; i-- {
		size += m.changes[i].write(bytes)
	}
	size += bytes.WriteTagAndLength(classUniversal, isCompound, tagSequence, size)
	size += m.object.write(bytes)
	size += bytes.WriteTagAndLength(classApplication, isCompound, TagModifyRequest, size)
	return
}

//
//        ModifyRequest ::= [APPLICATION 6] SEQUENCE {
//             object          LDAPDN,
//             changes         SEQUENCE OF change SEQUENCE {
//                  operation       ENUMERATED {
//                       add     (0),
//                       delete  (1),
//                       replace (2),
//                       ...  },
//                  modification    PartialAttribute } }
func (m ModifyRequest) size() (size int) {
	for _, change := range m.changes {
		size += change.size()
	}
	size += sizeTagAndLength(tagSequence, size)
	size += m.object.size()
	size += sizeTagAndLength(TagModifyRequest, size)
	return
}
func (m *ModifyRequest) Object() LDAPDN {
	return m.object
}
func (m *ModifyRequest) Changes() []ModifyRequestChange {
	return m.changes
}
