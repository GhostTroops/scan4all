package go_ora

import (
	"encoding/binary"
	"fmt"
	"github.com/sijms/go-ora/v2/network"
)

type urowid struct {
	data []byte
	rowid
}

func newURowID(session *network.Session) (*urowid, error) {
	length, err := session.GetInt(4, true, true)
	if err != nil {
		return nil, err
	}
	ret := new(urowid)
	if length > 0 {
		ret.data, err = session.GetClr()
		if err != nil {
			return nil, err
		}
		return ret, nil
	}
	return nil, nil
}
func (id *urowid) physicalRawIDToByteArray() []byte {
	// physical
	temp32 := binary.BigEndian.Uint32(id.data[1:5])
	id.rba = int64(temp32)
	temp16 := binary.BigEndian.Uint16(id.data[5:7])
	id.partitionID = int64(temp16)
	temp32 = binary.BigEndian.Uint32(id.data[7:11])
	id.blockNumber = int64(temp32)
	temp16 = binary.BigEndian.Uint16(id.data[11:13])
	id.slotNumber = int64(temp16)
	if id.rba == 0 {
		return []byte(fmt.Sprintf("%08X.%04X.%04X", id.blockNumber, id.slotNumber, id.partitionID))
	} else {
		return id.rowid.getBytes()
	}
}
func (id *urowid) logicalRawIDToByteArray() []byte {
	length1 := len(id.data)
	num1 := length1 / 3
	num2 := length1 % 3
	num3 := num1 * 4
	num4 := 0
	if num2 > 1 {
		num4 = 3
	} else {
		num4 = num2
	}
	length2 := num3 + num4
	var output []byte = nil
	if length2 > 0 {
		KGRD_INDBYTE_CHAR := []byte{65, 42, 45, 40, 41}
		var buffer = []byte{
			65, 66, 67, 68, 69, 70, 71, 72,
			73, 74, 75, 76, 77, 78, 79, 80,
			81, 82, 83, 84, 85, 86, 87, 88,
			89, 90, 97, 98, 99, 100, 101, 102,
			103, 104, 105, 106, 107, 108, 109, 110,
			111, 112, 113, 114, 115, 116, 117, 118,
			119, 120, 121, 122, 48, 49, 50, 51,
			52, 53, 54, 55, 56, 57, 43, 47,
		}
		output = make([]byte, length2)
		srcIndex := 0
		dstIndex := 1
		output[dstIndex] = KGRD_INDBYTE_CHAR[id.data[srcIndex]-1]
		length1 -= 1
		srcIndex++
		dstIndex++
		for length1 > 0 {
			output[dstIndex] = buffer[id.data[srcIndex]>>2]
			if length1 == 1 {
				output[dstIndex+1] = buffer[(id.data[srcIndex]&3)<<4]
				break
			}
			output[dstIndex+1] = buffer[(id.data[srcIndex]&3)<<4|(id.data[srcIndex+1]&0xF0)>>4]
			if length1 == 2 {
				output[dstIndex+2] = buffer[(id.data[srcIndex+1]&0xF)<<2]
				break
			}
			output[dstIndex+2] = buffer[(id.data[srcIndex+1]&0xF)<<2|(id.data[srcIndex+2]&0xC0)>>6]
			output[dstIndex+3] = buffer[id.data[srcIndex+2]&63]
			length1 -= 3
			srcIndex += 3
			dstIndex += 3
		}
	}
	return output
}
func (id *urowid) getBytes() []byte {
	if id.data[0] == 1 {
		return id.physicalRawIDToByteArray()
	} else {
		return id.logicalRawIDToByteArray()
	}
}

//private void ConvertToRestrictedFormat(riddef ridRowId, byte[] bytes)
//{
//	char paddingChar = '0';
//	StringBuilder stringBuilder = new StringBuilder();
//	stringBuilder.Append(Convert.ToString((long) ridRowId.ridblocknum, 16).PadLeft(8, paddingChar));
//	stringBuilder.Append('.');
//	stringBuilder.Append(Convert.ToString((int) ridRowId.ridslotnum, 16).PadLeft(4, paddingChar));
//	stringBuilder.Append('.');
//	stringBuilder.Append(Convert.ToString((int) ridRowId.idfilenum, 16).PadLeft(4, paddingChar));
//	string upperInvariant = stringBuilder.ToString().ToUpperInvariant();
//	int num = 0;
//	foreach (char ch in upperInvariant)
//	bytes[num++] = (byte) ch;
//}

//private void ConvertToExtendedFormat(riddef ridRowID, byte[] byteArray)
//{
//	int offset1 = 0;
//	uint ridobjnum = ridRowID.ridobjnum;
//	int offset2 = this.kgrd42b(byteArray, (long) ridobjnum, 6, offset1);
//	uint idfilenum = (uint) ridRowID.idfilenum;
//	int offset3 = this.kgrd42b(byteArray, (long) idfilenum, 3, offset2);
//	uint ridblocknum = ridRowID.ridblocknum;
//	int offset4 = this.kgrd42b(byteArray, (long) ridblocknum, 6, offset3);
//	uint ridslotnum = (uint) ridRowID.ridslotnum;
//	this.kgrd42b(byteArray, (long) ridslotnum, 3, offset4);
//}

//private byte[] LogicalROWIDToByteArray(byte[] byteStream)
//{
//byte[] dstBytes = (byte[]) null;
//int length1 = byteStream.Length;
//int num1 = length1 / 3;
//int num2 = length1 % 3;
//int num3 = 4 * num1;
//int num4;
//switch (num2)
//{
//case 0:
//num4 = 0;
//break;
//case 1:
//num4 = 1;
//break;
//default:
//num4 = 3;
//break;
//}
//int length2 = num3 + num4;
//if (length2 > 0)
//{
//dstBytes = new byte[length2];
//this.kgrdub2c(byteStream, length1, 0, dstBytes, 0);
//}
//return dstBytes;
//}

//private void kgrdub2c(byte[] id.data, int size, int offset, byte[] output, int dstOffset)
//{
//	output[dstOffset] = TTCRowIdAccessor.KGRD_INDBYTE_CHAR[(int)id.data[offset] - 1];
//	int num1 = size - 1;
//	offset ++;
//	dstOffset ++;
//	while (num1 > 0)
//	{
//		output[dstOffset] = (int)TTCRowIdAccessor.KGRD_BASIS_64[((int)id.data[offset] & (int)byte.MaxValue) >> 2];
//		if (num1 == 1)
//		{
//			output[dstOffset + 1] = (int)TTCRowIdAccessor.KGRD_BASIS_64[((int)id.data[offset] & 3) << 4];
//			break;
//		}
//		byte num11 = (byte)((uint)id.data[offset + 1] & (uint)byte.MaxValue);
//		int num15 = (int)TTCRowIdAccessor.KGRD_BASIS_64[((int)id.data[offset] & 3) << 4 | ((int)num11 & 240) >> 4];
//		output[dstOffset + 1] = (byte)num15;
//		if (num1 == 2)
//		{
//			int num10 = (int)TTCRowIdAccessor.KGRD_BASIS_64[((int)num11 & 15) << 2];
//			output[dstOffset + 2] = (byte)num10;
//			break;
//		}
//		int num19 = (int)TTCRowIdAccessor.KGRD_BASIS_64[((int)num11 & 15) << 2 | ((int)id.data[offset + 2] & 192) >> 6];
//		output[dstOffset + 2] = (byte)num19;
//		output[dstOffset + 3] = TTCRowIdAccessor.KGRD_BASIS_64[(int)id.data[offset + 2] & 63];
//		num1 -= 3;
//		offset += 3;
//		dstOffset += 3;
//	}
//}
