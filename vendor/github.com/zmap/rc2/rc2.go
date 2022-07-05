package rc2

import (
	"encoding/binary"
	"crypto/cipher"
	"errors"
)

var pitable []byte = []byte{
    0xd9, 0x78, 0xf9, 0xc4, 0x19, 0xdd, 0xb5, 0xed, 0x28, 0xe9, 0xfd, 0x79, 0x4a, 0xa0, 0xd8, 0x9d, 
    0xc6, 0x7e, 0x37, 0x83, 0x2b, 0x76, 0x53, 0x8e, 0x62, 0x4c, 0x64, 0x88, 0x44, 0x8b, 0xfb, 0xa2, 
    0x17, 0x9a, 0x59, 0xf5, 0x87, 0xb3, 0x4f, 0x13, 0x61, 0x45, 0x6d, 0x8d, 0x09, 0x81, 0x7d, 0x32, 
    0xbd, 0x8f, 0x40, 0xeb, 0x86, 0xb7, 0x7b, 0x0b, 0xf0, 0x95, 0x21, 0x22, 0x5c, 0x6b, 0x4e, 0x82, 
    0x54, 0xd6, 0x65, 0x93, 0xce, 0x60, 0xb2, 0x1c, 0x73, 0x56, 0xc0, 0x14, 0xa7, 0x8c, 0xf1, 0xdc, 
    0x12, 0x75, 0xca, 0x1f, 0x3b, 0xbe, 0xe4, 0xd1, 0x42, 0x3d, 0xd4, 0x30, 0xa3, 0x3c, 0xb6, 0x26, 
    0x6f, 0xbf, 0x0e, 0xda, 0x46, 0x69, 0x07, 0x57, 0x27, 0xf2, 0x1d, 0x9b, 0xbc, 0x94, 0x43, 0x03, 
    0xf8, 0x11, 0xc7, 0xf6, 0x90, 0xef, 0x3e, 0xe7, 0x06, 0xc3, 0xd5, 0x2f, 0xc8, 0x66, 0x1e, 0xd7, 
    0x08, 0xe8, 0xea, 0xde, 0x80, 0x52, 0xee, 0xf7, 0x84, 0xaa, 0x72, 0xac, 0x35, 0x4d, 0x6a, 0x2a, 
    0x96, 0x1a, 0xd2, 0x71, 0x5a, 0x15, 0x49, 0x74, 0x4b, 0x9f, 0xd0, 0x5e, 0x04, 0x18, 0xa4, 0xec, 
    0xc2, 0xe0, 0x41, 0x6e, 0x0f, 0x51, 0xcb, 0xcc, 0x24, 0x91, 0xaf, 0x50, 0xa1, 0xf4, 0x70, 0x39, 
    0x99, 0x7c, 0x3a, 0x85, 0x23, 0xb8, 0xb4, 0x7a, 0xfc, 0x02, 0x36, 0x5b, 0x25, 0x55, 0x97, 0x31, 
    0x2d, 0x5d, 0xfa, 0x98, 0xe3, 0x8a, 0x92, 0xae, 0x05, 0xdf, 0x29, 0x10, 0x67, 0x6c, 0xba, 0xc9, 
    0xd3, 0x00, 0xe6, 0xcf, 0xe1, 0x9e, 0xa8, 0x2c, 0x63, 0x16, 0x01, 0x3f, 0x58, 0xe2, 0x89, 0xa9, 
    0x0d, 0x38, 0x34, 0x1b, 0xab, 0x33, 0xff, 0xb0, 0xbb, 0x48, 0x0c, 0x5f, 0xb9, 0xb1, 0xcd, 0x2e, 
    0xc5, 0xf3, 0xdb, 0x47, 0xe5, 0xa5, 0x9c, 0x77, 0x0a, 0xa6, 0x20, 0x68, 0xfe, 0x7f, 0xc1, 0xad, 
}

func expandkey(ink []byte, bits uint) (outk [64]uint16) {
	var kx [128]byte

	t  := byte(len(ink))
	t8 := byte((bits+7) / 8)
	tm := byte(0xff >> ((uint(t8) * 8) - bits))

	copy(kx[0:], ink[0:])

	for i := t; i < 128; i++ {
		// L[i] = PITABLE[L[i-1] + L[i-T]];
		kx[i] = pitable[kx[i-1] + kx[i-t]]
	}

	// L[128-T8] = PITABLE[L[128-T8] & TM];
	kx[128-t8] = pitable[kx[128-t8] & tm]

	for i := 127 - int(t8); i >= 0; i-- {
		// L[i] = PITABLE[L[i+1] XOR L[i+T8]];
		kx[i] = pitable[kx[i+1] ^ kx[byte(i)+t8]]
	}

	for i := 0; i < len(outk); i++ {
		outk[i] = binary.LittleEndian.Uint16(kx[i * 2:])
	}

	return
}

func mixround(r []uint16, kx []uint16, j *uint) {
	var x uint16
	
	x = r[0] + (r[1] & (^r[3])) + (r[2] & r[3]) + kx[*j]; *j++
	r[0] = (x << 1) | (x >> 15)
	x = r[1] + (r[2] & (^r[0])) + (r[3] & r[0]) + kx[*j]; *j++
	r[1] = (x << 2) | (x >> 14)
	x = r[2] + (r[3] & (^r[1])) + (r[0] & r[1]) + kx[*j]; *j++
	r[2] = (x << 3) | (x >> 13)
	x = r[3] + (r[0] & (^r[2])) + (r[1] & r[2]) + kx[*j]; *j++
	r[3] = (x << 5) | (x >> 11)
}

func mashround(r []uint16, kx []uint16) {
	//   R[i] = R[i] + K[R[i-1] & 63];
	r[0] += kx[r[3] & 63]
	r[1] += kx[r[0] & 63]
	r[2] += kx[r[1] & 63]
	r[3] += kx[r[2] & 63]
}

func encrypt(r [4]uint16, kx []uint16) [4]uint16 {
	var j uint = 0

	mixround(r[0:], kx, &j)	// 0
	mixround(r[0:], kx, &j)	// 4	
	mixround(r[0:], kx, &j)	// 8	
	mixround(r[0:], kx, &j)	// 12	
	mixround(r[0:], kx, &j)	// 16	

	mashround(r[0:], kx)

	mixround(r[0:], kx, &j)	// 20	
	mixround(r[0:], kx, &j)	// 24	
	mixround(r[0:], kx, &j)	// 28	
	mixround(r[0:], kx, &j)	// 32	
	mixround(r[0:], kx, &j)	// 36	
	mixround(r[0:], kx, &j)	// 40	

	mashround(r[0:], kx)

	mixround(r[0:], kx, &j)	// 44	
	mixround(r[0:], kx, &j)	// 48	
	mixround(r[0:], kx, &j)	// 52	
	mixround(r[0:], kx, &j)	// 56	
	mixround(r[0:], kx, &j)	// 60	

	return r
}

func rmashround(r []uint16, kx []uint16) {
	//   R[i] = R[i] + K[R[i-1] & 63];
	r[3] -= kx[r[2] & 63]
	r[2] -= kx[r[1] & 63]
	r[1] -= kx[r[0] & 63]
	r[0] -= kx[r[3] & 63]
}

func rmixround(r []uint16, kx []uint16, j *uint) {
	var x uint16

	x = (r[3] << 11) | (r[3] >> 5)
	r[3] = x - ((r[0] & (^r[2])) + (r[1] & r[2]) + kx[*j]); *j--
	x = (r[2] << 13) | (r[2] >> 3)
	r[2] = x - ((r[3] & (^r[1])) + (r[0] & r[1]) + kx[*j]); *j--
	x = (r[1] << 14) | (r[1] >> 2)
	r[1] = x - ((r[2] & (^r[0])) + (r[3] & r[0]) + kx[*j]); *j--
	x = (r[0] << 15) | (r[0] >> 1)
	r[0] = x - ((r[1] & (^r[3])) + (r[2] & r[3]) + kx[*j]); *j--
}

func decrypt(r [4]uint16, kx []uint16) [4]uint16 {
	var j uint = 63
	
	rmixround(r[0:], kx, &j) 		
	rmixround(r[0:], kx, &j)		
	rmixround(r[0:], kx, &j)		
	rmixround(r[0:], kx, &j)		
	rmixround(r[0:], kx, &j)		

	rmashround(r[0:], kx)

	rmixround(r[0:], kx, &j)		
	rmixround(r[0:], kx, &j)		
	rmixround(r[0:], kx, &j)		
	rmixround(r[0:], kx, &j)		
	rmixround(r[0:], kx, &j)		
	rmixround(r[0:], kx, &j)		

	rmashround(r[0:], kx)

	rmixround(r[0:], kx, &j)		
	rmixround(r[0:], kx, &j)		
	rmixround(r[0:], kx, &j)		
	rmixround(r[0:], kx, &j)		
	rmixround(r[0:], kx, &j)		

	return r
}

type rc2cipher struct {
	xk [64]uint16
}

func (c *rc2cipher) BlockSize() int { return 8; }

func (c *rc2cipher) Decrypt(dst, src []byte) {
	var block [4]uint16
	block[0] = binary.LittleEndian.Uint16(src[0:])
	block[1] = binary.LittleEndian.Uint16(src[2:])
	block[2] = binary.LittleEndian.Uint16(src[4:])
	block[3] = binary.LittleEndian.Uint16(src[6:])
	block = decrypt(block, c.xk[0:])
	binary.LittleEndian.PutUint16(dst[0:], block[0])
	binary.LittleEndian.PutUint16(dst[2:], block[1])
	binary.LittleEndian.PutUint16(dst[4:], block[2])
	binary.LittleEndian.PutUint16(dst[6:], block[3])
}

func (c *rc2cipher) Encrypt(dst, src []byte) {
	var block [4]uint16
	block[0] = binary.LittleEndian.Uint16(src[0:])
	block[1] = binary.LittleEndian.Uint16(src[2:])
	block[2] = binary.LittleEndian.Uint16(src[4:])
	block[3] = binary.LittleEndian.Uint16(src[6:])
	block = encrypt(block, c.xk[0:])
	binary.LittleEndian.PutUint16(dst[0:], block[0])
	binary.LittleEndian.PutUint16(dst[2:], block[1])
	binary.LittleEndian.PutUint16(dst[4:], block[2])
	binary.LittleEndian.PutUint16(dst[6:], block[3])
}

func NewCipher(k []byte) (cipher.Block, error) {
	if len(k) < 1 || len(k) > 128 {
		return nil, errors.New("rc2: invalid key length 1 <= len(key) <= 128")
	}
	return &rc2cipher{ xk: expandkey(k, uint(len(k)*8)) }, nil
}

func NewCipherReducedStrength(k []byte, bits uint) (cipher.Block, error) {
	if len(k) < 1 || len(k) > 128 {
		return nil, errors.New("rc2: invalid key length (1 <= len(key) <= 128)")
	}
	if bits < 1 || bits > 1024 {
		return nil, errors.New("rc2: invalid number of effective bits (1 <= bits <= 1024)")
	}
	return &rc2cipher{ xk: expandkey(k, bits) }, nil
}


