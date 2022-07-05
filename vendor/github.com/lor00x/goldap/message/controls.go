package message

import "fmt"

//
//        Controls ::= SEQUENCE OF control Control

func readTaggedControls(bytes *Bytes, class int, tag int) (controls Controls, err error) {
	err = bytes.ReadSubBytes(class, tag, controls.readComponents)
	if err != nil {
		err = LdapError{fmt.Sprintf("readTaggedControls:\n%s", err.Error())}
		return
	}
	return
}
func (controls *Controls) readComponents(bytes *Bytes) (err error) {
	for bytes.HasMoreData() {
		var control Control
		control, err = readControl(bytes)
		if err != nil {
			err = LdapError{fmt.Sprintf("readComponents:\n%s", err.Error())}
			return
		}
		*controls = append(*controls, control)
	}
	return
}
func (controls Controls) Pointer() *Controls { return &controls }

func (controls Controls) writeTagged(bytes *Bytes, class int, tag int) (size int) {
	for i := len(controls) - 1; i >= 0; i-- {
		size += controls[i].write(bytes)
	}
	size += bytes.WriteTagAndLength(class, isCompound, tag, size)
	return
}

func (controls Controls) sizeTagged(tag int) (size int) {
	for _, control := range controls {
		size += control.size()
	}
	size += sizeTagAndLength(tag, size)
	return
}
