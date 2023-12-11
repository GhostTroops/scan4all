package core

import (
	"github.com/GhostTroops/scan4all/pkg/kscan/lib/grdp/glog"
	"unsafe"
)

func CVAL(p *[]uint8) int {
	a := int((*p)[0])
	*p = (*p)[1:]
	return a
}

func CVAL2(p *[]uint8, v *uint16) {
	*v = *((*uint16)(unsafe.Pointer(&(*p)[0])))
	//*v = binary.BigEndian.Uint16((*p)[0:2])
	//fmt.Println("*v:", *v)
	*p = (*p)[2:]
}

func REPEAT(f func(), count, x *int, width int) {
	for (*count & ^0x7) != 0 && ((*x + 8) < width) {
		for i := 0; i < 8; i++ {
			f()
			*count = *count - 1
			*x = *x + 1
		}
	}

	for (*count > 0) && (*x < width) {
		f()
		*count = *count - 1
		*x = *x + 1
	}
}

// /* 1 byte bitmap decompress */
// func bitmap_decompress1(uint8 * output, int width, int height, uint8 * input, int size) bool{
// 	uint8 *end = input + size;
// 	uint8 *prevline = NULL, *line = NULL;
// 	int opcode, count, offset, isfillormix, x = width;
// 	int lastopcode = -1, insertmix = false, bicolour = false;
// 	uint8 code;
// 	uint8 colour1 = 0, colour2 = 0;
// 	uint8 mixmask, mask = 0;
// 	uint8 mix = 0xff;
// 	int fom_mask = 0;

// 	for (input < end){
// 		fom_mask = 0;
// 		code = CVAL(input);
// 		opcode = code >> 4;
// 		/* Handle different opcode forms */
// 		switch (opcode){
// 			case 0xc:
// 			case 0xd:
// 			case 0xe:
// 				opcode -= 6;
// 				count = code & 0xf;
// 				offset = 16;
// 				break;
// 			case 0xf:
// 				opcode = code & 0xf;
// 				if (opcode < 9){
// 					count = CVAL(input);
// 					count |= CVAL(input) << 8;
// 				}else{
// 					count = (opcode < 0xb) ? 8 : 1;
// 				}
// 				offset = 0;
// 				break;
// 			default:
// 				opcode >>= 1;
// 				count = code & 0x1f;
// 				offset = 32;
// 				break;
// 		}
// 		/* Handle strange cases for counts */
// 		if (offset != 0){
// 			isfillormix = ((opcode == 2) || (opcode == 7));
// 			if (count == 0){
// 				if (isfillormix)
// 					count = CVAL(input) + 1;
// 				else
// 					count = CVAL(input) + offset;
// 			}else if (isfillormix){
// 				count <<= 3;
// 			}
// 		}
// 		/* Read preliminary data */
// 		switch (opcode){
// 			case 0:	/* Fill */
// 				if ((lastopcode == opcode) && !((x == width) && (prevline == NULL))){
// 					insertmix = true;
//                }
// 				break;
// 			case 8:	/* Bicolour */
// 				colour1 = CVAL(input);
// 			case 3:	/* Colour */
// 				colour2 = CVAL(input);
// 				break;
// 			case 6:	/* SetMix/Mix */
// 			case 7:	/* SetMix/FillOrMix */
// 				mix = CVAL(input);
// 				opcode -= 5;
// 				break;
// 			case 9:	/* FillOrMix_1 */
// 				mask = 0x03;
// 				opcode = 0x02;
// 				fom_mask = 3;
// 				break;
// 			case 0x0a:	/* FillOrMix_2 */
// 				mask = 0x05;
// 				opcode = 0x02;
// 				fom_mask = 5;
// 				break;
// 		}
// 		lastopcode = opcode;
// 		mixmask = 0;
// 		/* Output body */
// 		for (count > 0){
// 			if (x >= width){
// 				if (height <= 0)
// 					return false;
// 				x = 0;
// 				height--;
// 				prevline = line;
// 				line = output + height * width;
// 			}
// 			switch (opcode){
// 				case 0:	/* Fill */
// 					if (insertmix){
// 						if (prevline == NULL)
// 							line[x] = mix;
// 						else
// 							line[x] = prevline[x] ^ mix;
// 						insertmix = false;
// 						count--;
// 						x++;
// 					}
// 					if (prevline == NULL){
// 						REPEAT(line[x] = 0)
// 					}else{
// 						REPEAT(line[x] = prevline[x])
// 					}
// 					break;
// 				case 1:	/* Mix */
// 					if (prevline == NULL){
// 						REPEAT(line[x] = mix)
// 					}else{
// 						REPEAT(line[x] = prevline[x] ^ mix)
// 					}
// 					break;
// 				case 2:	/* Fill or Mix */
// 					if (prevline == NULL){
// 						REPEAT
// 						(
// 							MASK_UPDATE();
// 							if (mask & mixmask)
// 								line[x] = mix;
// 							else
// 								line[x] = 0;
// 						)
// 					}else{
// 						REPEAT
// 						(
// 							MASK_UPDATE();
// 							if (mask & mixmask)
// 								line[x] = prevline[x] ^ mix;
// 							else
// 								line[x] = prevline[x];
// 						)
// 					}
// 					break;
// 				case 3:	/* Colour */
// 					REPEAT(line[x] = colour2)
// 					break;
// 				case 4:	/* Copy */
// 					REPEAT(line[x] = CVAL(input))
// 					break;
// 				case 8:	/* Bicolour */
// 					REPEAT
// 					(
// 						if (bicolour)
// 						{
// 							line[x] = colour2;
// 							bicolour = false;
// 						}
// 						else
// 						{
// 							line[x] = colour1;
// 							bicolour = true; count++;
// 						}
// 					)
// 					break;
// 				case 0xd:	/* White */
// 					REPEAT(line[x] = 0xff)
// 					break;
// 				case 0xe:	/* Black */
// 					REPEAT(line[x] = 0)
// 					break;
// 				default:
// 					fmt.Printf("bitmap opcode 0x%x\n", opcode);
// 					return false;
// 			}
// 		}
// 	}
// 	return true;
// }

// /* 2 byte bitmap decompress */
func decompress2(output *[]uint8, width, height int, input []uint8, size int) bool {
	var (
		prevline, line                   int
		opcode, count, offset, code      int
		x                                int = width
		lastopcode                       int = -1
		insertmix, bicolour, isfillormix bool
		mixmask, mask                    uint8
		colour1, colour2                 uint16
		mix                              uint16 = 0xffff
		fom_mask                         uint8
	)

	out := make([]uint16, width*height)
	for len(input) != 0 {
		fom_mask = 0
		code = CVAL(&input)
		opcode = code >> 4
		/* Handle different opcode forms */
		switch opcode {
		case 0xc, 0xd, 0xe:
			opcode -= 6
			count = code & 0xf
			offset = 16
			break
		case 0xf:
			opcode = code & 0xf
			if opcode < 9 {
				count = CVAL(&input)
				count |= CVAL(&input) << 8
			} else {
				count = 1
				if opcode < 0xb {
					count = 8
				}
			}
			offset = 0
			break
		default:
			opcode >>= 1
			count = code & 0x1f
			offset = 32
			break
		}

		/* Handle strange cases for counts */
		if offset != 0 {
			isfillormix = ((opcode == 2) || (opcode == 7))
			if count == 0 {
				if isfillormix {
					count = CVAL(&input) + 1
				} else {
					count = CVAL(&input) + offset
				}
			} else if isfillormix {
				count <<= 3
			}
		}
		/* Read preliminary data */
		switch opcode {
		case 0: /* Fill */
			if (lastopcode == opcode) && !((x == width) && (prevline == 0)) {
				insertmix = true
			}
			break
		case 8: /* Bicolour */
			CVAL2(&input, &colour1)
			CVAL2(&input, &colour2)
			break
		case 3: /* Colour */
			CVAL2(&input, &colour2)
			break
		case 6: /* SetMix/Mix */
			fallthrough
		case 7: /* SetMix/FillOrMix */
			CVAL2(&input, &mix)
			opcode -= 5
			break
		case 9: /* FillOrMix_1 */
			mask = 0x03
			opcode = 0x02
			fom_mask = 3
			break
		case 0x0a: /* FillOrMix_2 */
			mask = 0x05
			opcode = 0x02
			fom_mask = 5
			break
		}
		lastopcode = opcode
		mixmask = 0
		/* Output body */
		for count > 0 {
			if x >= width {
				if height <= 0 {
					return false
				}

				x = 0
				height--
				prevline = line
				line = height * width
			}
			switch opcode {
			case 0: /* Fill */
				if insertmix {
					if prevline == 0 {
						out[x+line] = mix
					} else {
						out[x+line] = out[prevline+x] ^ mix
					}
					insertmix = false
					count--
					x++
				}
				if prevline == 0 {
					REPEAT(func() {
						out[x+line] = 0
					}, &count, &x, width)
				} else {
					REPEAT(func() {
						out[x+line] = out[prevline+x]
					}, &count, &x, width)
				}
				break
			case 1: /* Mix */
				if prevline == 0 {
					REPEAT(func() {
						out[x+line] = mix
					}, &count, &x, width)
				} else {
					REPEAT(func() {
						out[x+line] = out[prevline+x] ^ mix
					}, &count, &x, width)
				}
				break
			case 2: /* Fill or Mix */
				if prevline == 0 {
					REPEAT(func() {
						mixmask <<= 1
						if mixmask == 0 {
							mask = fom_mask
							if fom_mask == 0 {
								mask = uint8(CVAL(&input))
								mixmask = 1
							}
						}
						if mask&mixmask != 0 {
							out[x+line] = mix
						} else {
							out[x+line] = 0
						}
					}, &count, &x, width)
				} else {
					REPEAT(func() {
						mixmask = mixmask << 1
						if mixmask == 0 {
							mask = fom_mask
							if fom_mask == 0 {
								mask = uint8(CVAL(&input))
								mixmask = 1
							}
						}
						if mask&mixmask != 0 {
							out[x+line] = out[prevline+x] ^ mix
						} else {
							out[x+line] = out[prevline+x]
						}
					}, &count, &x, width)
				}
				break
			case 3: /* Colour */
				REPEAT(func() {
					out[x+line] = colour2
				}, &count, &x, width)
				break
			case 4: /* Copy */
				REPEAT(func() {
					var a uint16
					CVAL2(&input, &a)
					out[x+line] = a
				}, &count, &x, width)

				break
			case 8: /* Bicolour */
				REPEAT(func() {
					if bicolour {
						out[x+line] = colour2
						bicolour = false
					} else {
						out[x+line] = colour1
						bicolour = true
						count++
					}
				}, &count, &x, width)

				break
			case 0xd: /* White */
				REPEAT(func() {
					out[x+line] = 0xffff
				}, &count, &x, width)
				break
			case 0xe: /* Black */
				REPEAT(func() {
					out[x+line] = 0
				}, &count, &x, width)
				break
			default:
				glog.Infof("bitmap opcode 0x%x\n", opcode)
				return false
			}
		}
	}
	j := 0
	for _, v := range out {
		(*output)[j], (*output)[j+1] = PutUint16BE(v)
		j += 2
	}
	return true
}

// /* 3 byte bitmap decompress */
// func bitmap_decompress3(uint8 * output, int width, int height, uint8 * input, int size)bool{
// 	uint8 *end = input + size;
// 	uint8 *prevline = NULL, *line = NULL;
// 	int opcode, count, offset, isfillormix, x = width;
// 	int lastopcode = -1, insertmix = false, bicolour = false;
// 	uint8 code;
// 	uint8 colour1[3] = {0, 0, 0}, colour2[3] = {0, 0, 0};
// 	uint8 mixmask, mask = 0;
// 	uint8 mix[3] = {0xff, 0xff, 0xff};
// 	int fom_mask = 0;

// 	while (input < end)
// 	{
// 		fom_mask = 0;
// 		code = CVAL(input);
// 		opcode = code >> 4;
// 		/* Handle different opcode forms */
// 		switch (opcode)
// 		{
// 			case 0xc:
// 			case 0xd:
// 			case 0xe:
// 				opcode -= 6;
// 				count = code & 0xf;
// 				offset = 16;
// 				break;
// 			case 0xf:
// 				opcode = code & 0xf;
// 				if (opcode < 9)
// 				{
// 					count = CVAL(input);
// 					count |= CVAL(input) << 8;
// 				}
// 				else
// 				{
// 					count = (opcode <
// 						 0xb) ? 8 : 1;
// 				}
// 				offset = 0;
// 				break;
// 			default:
// 				opcode >>= 1;
// 				count = code & 0x1f;
// 				offset = 32;
// 				break;
// 		}
// 		/* Handle strange cases for counts */
// 		if (offset != 0)
// 		{
// 			isfillormix = ((opcode == 2) || (opcode == 7));
// 			if (count == 0)
// 			{
// 				if (isfillormix)
// 					count = CVAL(input) + 1;
// 				else
// 					count = CVAL(input) + offset;
// 			}
// 			else if (isfillormix)
// 			{
// 				count <<= 3;
// 			}
// 		}
// 		/* Read preliminary data */
// 		switch (opcode)
// 		{
// 			case 0:	/* Fill */
// 				if ((lastopcode == opcode) && !((x == width) && (prevline == NULL)))
// 					insertmix = true;
// 				break;
// 			case 8:	/* Bicolour */
// 				colour1[0] = CVAL(input);
// 				colour1[1] = CVAL(input);
// 				colour1[2] = CVAL(input);
// 			case 3:	/* Colour */
// 				colour2[0] = CVAL(input);
// 				colour2[1] = CVAL(input);
// 				colour2[2] = CVAL(input);
// 				break;
// 			case 6:	/* SetMix/Mix */
// 			case 7:	/* SetMix/FillOrMix */
// 				mix[0] = CVAL(input);
// 				mix[1] = CVAL(input);
// 				mix[2] = CVAL(input);
// 				opcode -= 5;
// 				break;
// 			case 9:	/* FillOrMix_1 */
// 				mask = 0x03;
// 				opcode = 0x02;
// 				fom_mask = 3;
// 				break;
// 			case 0x0a:	/* FillOrMix_2 */
// 				mask = 0x05;
// 				opcode = 0x02;
// 				fom_mask = 5;
// 				break;
// 		}
// 		lastopcode = opcode;
// 		mixmask = 0;
// 		/* Output body */
// 		while (count > 0)
// 		{
// 			if (x >= width)
// 			{
// 				if (height <= 0)
// 					return false;
// 				x = 0;
// 				height--;
// 				prevline = line;
// 				line = output + height * (width * 3);
// 			}
// 			switch (opcode)
// 			{
// 				case 0:	/* Fill */
// 					if (insertmix)
// 					{
// 						if (prevline == NULL)
// 						{
// 							line[x * 3] = mix[0];
// 							line[x * 3 + 1] = mix[1];
// 							line[x * 3 + 2] = mix[2];
// 						}
// 						else
// 						{
// 							line[x * 3] =
// 							 prevline[x * 3] ^ mix[0];
// 							line[x * 3 + 1] =
// 							 prevline[x * 3 + 1] ^ mix[1];
// 							line[x * 3 + 2] =
// 							 prevline[x * 3 + 2] ^ mix[2];
// 						}
// 						insertmix = false;
// 						count--;
// 						x++;
// 					}
// 					if (prevline == NULL)
// 					{
// 						REPEAT
// 						(
// 							line[x * 3] = 0;
// 							line[x * 3 + 1] = 0;
// 							line[x * 3 + 2] = 0;
// 						)
// 					}
// 					else
// 					{
// 						REPEAT
// 						(
// 							line[x * 3] = prevline[x * 3];
// 							line[x * 3 + 1] = prevline[x * 3 + 1];
// 							line[x * 3 + 2] = prevline[x * 3 + 2];
// 						)
// 					}
// 					break;
// 				case 1:	/* Mix */
// 					if (prevline == NULL)
// 					{
// 						REPEAT
// 						(
// 							line[x * 3] = mix[0];
// 							line[x * 3 + 1] = mix[1];
// 							line[x * 3 + 2] = mix[2];
// 						)
// 					}
// 					else
// 					{
// 						REPEAT
// 						(
// 							line[x * 3] =
// 							 prevline[x * 3] ^ mix[0];
// 							line[x * 3 + 1] =
// 							 prevline[x * 3 + 1] ^ mix[1];
// 							line[x * 3 + 2] =
// 							 prevline[x * 3 + 2] ^ mix[2];
// 						)
// 					}
// 					break;
// 				case 2:	/* Fill or Mix */
// 					if (prevline == NULL)
// 					{
// 						REPEAT
// 						(
// 							MASK_UPDATE();
// 							if (mask & mixmask)
// 							{
// 								line[x * 3] = mix[0];
// 								line[x * 3 + 1] = mix[1];
// 								line[x * 3 + 2] = mix[2];
// 							}
// 							else
// 							{
// 								line[x * 3] = 0;
// 								line[x * 3 + 1] = 0;
// 								line[x * 3 + 2] = 0;
// 							}
// 						)
// 					}
// 					else
// 					{
// 						REPEAT
// 						(
// 							MASK_UPDATE();
// 							if (mask & mixmask)
// 							{
// 								line[x * 3] =
// 								 prevline[x * 3] ^ mix [0];
// 								line[x * 3 + 1] =
// 								 prevline[x * 3 + 1] ^ mix [1];
// 								line[x * 3 + 2] =
// 								 prevline[x * 3 + 2] ^ mix [2];
// 							}
// 							else
// 							{
// 								line[x * 3] =
// 								 prevline[x * 3];
// 								line[x * 3 + 1] =
// 								 prevline[x * 3 + 1];
// 								line[x * 3 + 2] =
// 								 prevline[x * 3 + 2];
// 							}
// 						)
// 					}
// 					break;
// 				case 3:	/* Colour */
// 					REPEAT
// 					(
// 						line[x * 3] = colour2 [0];
// 						line[x * 3 + 1] = colour2 [1];
// 						line[x * 3 + 2] = colour2 [2];
// 					)
// 					break;
// 				case 4:	/* Copy */
// 					REPEAT
// 					(
// 						line[x * 3] = CVAL(input);
// 						line[x * 3 + 1] = CVAL(input);
// 						line[x * 3 + 2] = CVAL(input);
// 					)
// 					break;
// 				case 8:	/* Bicolour */
// 					REPEAT
// 					(
// 						if (bicolour)
// 						{
// 							line[x * 3] = colour2[0];
// 							line[x * 3 + 1] = colour2[1];
// 							line[x * 3 + 2] = colour2[2];
// 							bicolour = false;
// 						}
// 						else
// 						{
// 							line[x * 3] = colour1[0];
// 							line[x * 3 + 1] = colour1[1];
// 							line[x * 3 + 2] = colour1[2];
// 							bicolour = true;
// 							count++;
// 						}
// 					)
// 					break;
// 				case 0xd:	/* White */
// 					REPEAT
// 					(
// 						line[x * 3] = 0xff;
// 						line[x * 3 + 1] = 0xff;
// 						line[x * 3 + 2] = 0xff;
// 					)
// 					break;
// 				case 0xe:	/* Black */
// 					REPEAT
// 					(
// 						line[x * 3] = 0;
// 						line[x * 3 + 1] = 0;
// 						line[x * 3 + 2] = 0;
// 					)
// 					break;
// 				default:
// 					fmt.Printf("bitmap opcode 0x%x\n", opcode);
// 					return false;
// 			}
// 		}
// 	}
// 	return true;
// }

/* decompress a colour plane */
func processPlane(in *[]uint8, width, height int, output *[]uint8, j int) int {
	var (
		indexw   int
		indexh   int
		code     int
		collen   int
		replen   int
		color    int
		x        int
		revcode  int
		lastline int
		thisline int
	)
	ln := len(*in)

	lastline = 0
	indexh = 0
	i := 0
	for indexh < height {
		thisline = j + (width * height * 4) - ((indexh + 1) * width * 4)
		color = 0
		indexw = 0
		i = thisline

		if lastline == 0 {
			for indexw < width {
				code = CVAL(in)
				replen = code & 0xf
				collen = (code >> 4) & 0xf
				revcode = (replen << 4) | collen
				if (revcode <= 47) && (revcode >= 16) {
					replen = revcode
					collen = 0
				}
				for collen > 0 {
					color = CVAL(in)
					(*output)[i] = uint8(color)
					i += 4

					indexw++
					collen--
				}
				for replen > 0 {
					(*output)[i] = uint8(color)
					i += 4
					indexw++
					replen--
				}
			}
		} else {
			for indexw < width {
				code = CVAL(in)
				replen = code & 0xf
				collen = (code >> 4) & 0xf
				revcode = (replen << 4) | collen
				if (revcode <= 47) && (revcode >= 16) {
					replen = revcode
					collen = 0
				}
				for collen > 0 {
					x = CVAL(in)
					if x&1 != 0 {
						x = x >> 1
						x = x + 1
						color = -x
					} else {
						x = x >> 1
						color = x
					}
					x = int((*output)[indexw*4+lastline]) + color
					(*output)[i] = uint8(x)
					i += 4
					indexw++
					collen--
				}
				for replen > 0 {
					x = int((*output)[indexw*4+lastline]) + color
					(*output)[i] = uint8(x)
					i += 4
					indexw++
					replen--
				}
			}
		}
		indexh++
		lastline = thisline
	}
	return ln - len(*in)
}

/* 4 byte bitmap decompress */
func decompress4(output *[]uint8, width, height int, input []uint8, size int) bool {
	var (
		code             int
		onceBytes, total int
	)

	code = CVAL(&input)
	if code != 0x10 {
		return false
	}

	total = 1
	onceBytes = processPlane(&input, width, height, output, 3)
	total += onceBytes

	onceBytes = processPlane(&input, width, height, output, 2)
	total += onceBytes

	onceBytes = processPlane(&input, width, height, output, 1)
	total += onceBytes

	onceBytes = processPlane(&input, width, height, output, 0)
	total += onceBytes

	return size == total
}

/* main decompress function */
func Decompress(input []uint8, width, height int, Bpp int) []uint8 {
	size := width * height * Bpp
	output := make([]uint8, size)
	switch Bpp {
	case 1:
		//decompress1(output, width, height, input, size)
	case 2:
		decompress2(&output, width, height, input, size)
	case 3:
		//decompress3(output, width, height, input, size)
	case 4:
		decompress4(&output, width, height, input, size)
	default:
		glog.Infof("Bpp %d\n", Bpp)
	}

	return output
}
