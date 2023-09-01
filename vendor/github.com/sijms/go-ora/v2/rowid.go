package go_ora

import (
	"github.com/sijms/go-ora/v2/network"
)

type rowid struct {
	rba         int64
	partitionID int64
	filter      byte
	blockNumber int64
	slotNumber  int64
}

// newRowID read rowId from network session
func newRowID(session *network.Session) (*rowid, error) {
	temp, err := session.GetByte()
	if err != nil {
		return nil, err
	}
	if temp > 0 {
		ret := new(rowid)
		ret.rba, err = session.GetInt64(4, true, true)
		if err != nil {
			return nil, err
		}
		ret.partitionID, err = session.GetInt64(2, true, true)
		if err != nil {
			return nil, err
		}
		num, err := session.GetByte()
		if err != nil {
			return nil, err
		}
		ret.blockNumber, err = session.GetInt64(4, true, true)
		if err != nil {
			return nil, err
		}
		ret.slotNumber, err = session.GetInt64(2, true, true)
		if err != nil {
			return nil, err
		}
		if ret.rba == 0 && ret.partitionID == 0 && num == 0 && ret.blockNumber == 0 && ret.slotNumber == 0 {
			return nil, nil
		}
		return ret, nil
	}
	return nil, nil
}

func convertRowIDToByte(number int64, size int) []byte {
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
	output := make([]byte, size)
	for x := size; x > 0; x-- {
		output[x-1] = buffer[number&0x3F]
		if number >= 0 {
			number = number >> 6
		} else {
			number = (number >> 6) + (2 << (32 + ^6))
		}
	}
	return output
}

func (id *rowid) getBytes() []byte {
	output := make([]byte, 0, 18)
	output = append(output, convertRowIDToByte(id.rba, 6)...)
	output = append(output, convertRowIDToByte(id.partitionID, 3)...)
	output = append(output, convertRowIDToByte(id.blockNumber, 6)...)
	output = append(output, convertRowIDToByte(id.slotNumber, 3)...)
	return output
}

//// internal static long URShift(long number, int bits) => number >= 0L ? number >> bits : (number >> bits) + (2L << ~bits);
