package converters

import (
	"encoding/binary"
	"unicode/utf16"
	"unsafe"
)

type IStringConverter interface {
	Encode(string) []byte
	Decode([]byte) string
	GetLangID() int
	//SetLangID(langID int) int
}

type StringConverter struct {
	LangID    int
	CharWidth int
	eReplace  int
	dReplace  int
	dBuffer   []int
	dBuffer2  []int
	eBuffer   map[int]int
}

func MaxBytePerChar(charsetID int) int {
	switch charsetID {
	case 0x33D:
		return 2
	case 0x33E:
		fallthrough
	case 0x33F:
		return 3
	case 0x340:
		return 2
	case 0x352:
		fallthrough
	case 0x353:
		fallthrough
	case 0x354:
		return 2
	case 870:
		fallthrough
	case 871:
		return 3
	case 872:
		fallthrough
	case 873:
		return 4
	case 2000:
		fallthrough
	case 2002:
		return 2
	default:
		return 1
	}
}
func (conv *StringConverter) GetLangID() int {
	return conv.LangID
}

//func (conv *StringConverter) SetLangID(langID int) int {
//	oldValue := conv.LangID
//	conv.LangID = langID
//	return oldValue
//}

func (conv *StringConverter) Encode(input string) []byte {
	if len(input) == 0 {
		return nil
	}
	temp := utf16.Encode([]rune(input))
	switch conv.LangID {
	case 870:
		fallthrough
	case 871:
		fallthrough
	case 872:
		fallthrough
	case 873: // 32bit utf-8
		// utf-8 encoding
		return []byte(input)
	case 2000:
		output := make([]byte, 0, len(temp)*2)
		for x := 0; x < len(temp); x++ {
			tempbyte := []byte{0, 0}
			binary.BigEndian.PutUint16(tempbyte, temp[x])
			output = append(output, tempbyte...)
		}
		return output
	case 2002:
		output := make([]byte, 0, len(temp)*2)
		for x := 0; x < len(temp); x++ {
			tempbyte := []byte{0, 0}
			binary.LittleEndian.PutUint16(tempbyte, temp[x])
			output = append(output, tempbyte...)
		}
		return output
	default:
		if conv.eBuffer == nil {
			return []byte(input)
		}
		output := make([]byte, 0, len(temp))
		for x := 0; x < len(temp); x++ {
			if ch, ok := conv.eBuffer[int(temp[x])]; ok {
				if ch < 0x100 {
					output = append(output, uint8(ch))
				} else if ch < 0x10000 {
					output = append(output, uint8(ch>>8), uint8(ch))
				} else {
					output = append(output, uint8(ch>>24), uint8(ch>>16), uint8(ch>>8), uint8(ch))
				}
			} else {
				output = append(output, uint8(conv.eReplace))
				// output[x] = uint8(conv.eReplace)
			}
		}
		return output
	}
}

func (conv *StringConverter) Decode(input []byte) string {
	if len(input) == 0 {
		return ""
	}
	switch conv.LangID {
	case 870:
		fallthrough
	case 871:
		fallthrough
	case 872:
		fallthrough
	case 873:
		// utf-8 encoding
		return BytesToString(input)
	case 2000:
		index := 0
		var inputData []byte
		if len(input)%2 > 0 {
			inputData = make([]byte, len(input))
			copy(inputData, input)
			input = append(inputData, 0)
		}
		output := make([]uint16, len(input)/2)
		for index < len(input) {
			output[index/2] = binary.BigEndian.Uint16(input[index : index+2])
			index += 2
		}
		return string(utf16.Decode(output))
	case 2002:
		index := 0
		var inputData []byte
		if len(input)%2 > 0 {
			inputData = make([]byte, len(input))
			copy(inputData, input)
			input = append(inputData, 0)
		}
		output := make([]uint16, len(input)/2)
		for index < len(input) {
			output[index/2] = binary.LittleEndian.Uint16(input[index : index+2])
			index += 2
		}
		return string(utf16.Decode(output))
	case 0x33D:
		fallthrough
	case 0x352:
		fallthrough
	case 0x353:
		index := 0
		result := 0
		output := make([]uint16, 0, len(input))
		for index < len(input) {
			if input[index] > 127 {
				if index+1 > len(input) {
					return string(input)
				}
				result = int(binary.BigEndian.Uint16(input[index:]))
				index++
			} else {
				result = int(input[index])
			}
			index++
			index1 := (result >> 8) & 0xFF
			index2 := result & 0xFF
			char1 := conv.dBuffer[index1]
			if char1 == 0xFFFF {
				output = append(output, uint16(conv.dReplace))
				continue
			}
			char := conv.dBuffer2[char1+index2]
			if char == 0xFFFF {
				output = append(output, uint16(conv.dReplace))
				continue
			}
			if uint(char) > 0xFFFF {
				output = append(output, uint16(char>>16))
			}
			output = append(output, uint16(char))
		}
		return string(utf16.Decode(output))
	case 0x354:
		index := 0
		result := 0
		output := make([]uint16, 0, len(input))
		for index < len(input) {
			if input[index] > 128 {
				if index+1 > len(input) {
					return string(input)
				}
				result = int(binary.BigEndian.Uint16(input[index:]))
				index++
			} else {
				result = int(input[index])
			}
			index++
			index1 := (result >> 8) & 0xFF
			index2 := result & 0xFF
			char1 := conv.dBuffer[index1]
			if char1 == 0xFFFF {
				output = append(output, uint16(conv.dReplace))
				continue
			}
			char := conv.dBuffer2[char1+index2]
			if char == 0xFFFF {
				output = append(output, uint16(conv.dReplace))
				continue
			}
			if uint(char) > 0xFFFF {
				output = append(output, uint16(char>>16))
			}
			output = append(output, uint16(char))
		}
		return string(utf16.Decode(output))
	case 0x33E:
		fallthrough
	case 0x33F:
		index := 0
		num6 := 0
		charWidth := 0
		result := 0
		output := make([]uint16, 0, len(input))
		for index < len(input) {
			if input[index] == 0x8F {
				charWidth = 3
				num6 = 0x100
				index++
				if index+2 > len(input) {
					return string(input)
				}
				result = int(binary.BigEndian.Uint16(input[index:]))
				index--
			} else if input[index] > 0x7F {
				charWidth = 2
				result = int(binary.BigEndian.Uint16(input[index:]))
			} else {
				charWidth = 1
				result = int(input[index])
			}
			index += charWidth
			index1 := ((result >> 8) & 0xFF) + num6
			index2 := result & 0xFF
			char1 := conv.dBuffer[index1]
			if char1 == 0xFFFF {
				output = append(output, uint16(conv.dReplace))
				continue
			}
			char := conv.dBuffer2[char1+index2]
			if char == 0xFFFF {
				output = append(output, uint16(conv.dReplace))
				continue
			}
			if uint(char) > 0xFFFF {
				output = append(output, uint16(char>>16))
			}
			output = append(output, uint16(char))
		}
		return string(utf16.Decode(output))
	case 0x340:
		index := 0
		result := 0
		output := make([]uint16, 0, len(input))
		for index < len(input) {
			if input[index] > 223 || input[index] > 127 && input[index] < 161 {
				if index+1 > len(input) {
					return string(input)
				}
				result = int(binary.BigEndian.Uint16(input[index:]))
				index++
			} else {
				result = int(input[index])
			}
			index++
			index1 := (result >> 8) & 0xFF
			index2 := result & 0xFF
			char1 := conv.dBuffer[index1]
			if char1 == 0xFFFF {
				output = append(output, uint16(conv.dReplace))
				continue
			}
			char := conv.dBuffer2[char1+index2]
			if char == 0xFFFF {
				output = append(output, uint16(conv.dReplace))
				continue
			}
			if uint(char) > 0xFFFF {
				output = append(output, uint16(char>>16))
			}
			output = append(output, uint16(char))
		}
		return string(utf16.Decode(output))
	default:
		if conv.dBuffer == nil {
			return string(input)
		}
		output := make([]uint16, len(input))
		for x := 0; x < len(input); x++ {
			index := int(input[x])
			if index >= len(conv.dBuffer) {
				output[x] = uint16(conv.dReplace)
			} else {
				output[x] = uint16(conv.dBuffer[input[x]])
				// change number to byte
				if output[x] == 0xFFFF {
					output[x] = uint16(conv.dReplace)
				}
			}

		}
		return string(utf16.Decode(output))
	}
}

func BytesToString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}
