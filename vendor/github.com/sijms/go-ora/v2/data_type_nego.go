package go_ora

import (
	"errors"
	"fmt"
	"github.com/sijms/go-ora/v2/network"
	"time"
)

type DataTypeNego struct {
	MessageCode            uint8
	Server                 *TCPNego
	TypeAndRep             []int16
	RuntimeTypeAndRep      []int16
	DataTypeRepFor1100     int16
	DataTypeRepFor1200     int16
	CompileTimeCaps        []byte
	RuntimeCap             []byte
	DBTimeZone             []byte
	b32kTypeSupported      bool
	supportSessionStateOps bool
	serverTZVersion        int
	clientTZVersion        int
}

const (
	bufferGrow             int   = 2369
	TNS_TYPE_REP_NATIVE    int16 = 0
	TNS_TYPE_REP_UNIVERSAL int16 = 1
	TNS_TYPE_REP_ORACLE    int16 = 10
	TNS_DATA_TYPE_UB2      int16 = 25
	TNS_DATA_TYPE_UB4      int16 = 26
	TNS_DATA_TYPE_SB1      int16 = 27
	TNS_DATA_TYPE_SB2      int16 = 28
	TNS_DATA_TYPE_SB4      int16 = 29
	TNS_DATA_TYPE_SWORD    int16 = 30
	TNS_DATA_TYPE_UWORD    int16 = 31
	TNS_DATA_TYPE_PTRB     int16 = 32
	TNS_DATA_TYPE_PTRW     int16 = 33
	TNS_DATA_TYPE_TIDDEF   int16 = 10
)

func (n *DataTypeNego) addTypeRep(dty int16, ndty int16, rep int16) {
	if n.TypeAndRep == nil {
		n.TypeAndRep = make([]int16, bufferGrow)
	}
	if len(n.TypeAndRep) < int(n.TypeAndRep[0]+4) {
		n.TypeAndRep = append(n.TypeAndRep, make([]int16, bufferGrow)...)
	}
	index := n.TypeAndRep[0]
	n.TypeAndRep[index] = dty
	n.TypeAndRep[index+1] = ndty
	if ndty == 0 {
		n.TypeAndRep[0] = index + 2
	} else {
		n.TypeAndRep[index+2] = rep
		n.TypeAndRep[index+3] = 0
		n.TypeAndRep[0] = index + 4
	}
}

func buildTypeNego(nego *TCPNego, session *network.Session) *DataTypeNego {
	result := DataTypeNego{
		MessageCode: 2,
		Server:      nego,
		TypeAndRep:  make([]int16, bufferGrow),
		CompileTimeCaps: []byte{
			6, 1, 0, 0, 106, 1, 1, 11,
			1, 1, 1, 1, 1, 1, 0, 41,
			144, 3, 7, 3, 0, 1, 0, 235,
			1, 0, 5, 1, 0, 0, 0, 24,
			0, 0, 7, 32, 2, 58, 0, 0, 5,
		},
		//CompileTimeCaps: []byte{0x6, 0x1, 0x1, 0x1, 0x6f, 0x1, 0x1, 0x10,
		//	0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x1, 0x7f,
		//	0xff, 0x3, 0x10, 0x3, 0x3, 0x1, 0x1, 0xff,
		//	0x1, 0xff, 0xff, 0x1, 0xb, 0x1, 0x1, 0xff,
		//	0x1, 0x6, 0xc, 0xe6, 0x1, 0x7f, 0x5, 0xf,
		//	0x7f, 0xd, 0x3, 0, 0x1},
		RuntimeCap: []byte{2, 1, 0, 0, 0, 0, 0},
		//RuntimeCap:             []byte{2, 1, 0, 0, 18, 0, 87},
		b32kTypeSupported:      false,
		supportSessionStateOps: false,
		clientTZVersion:        0x20,
	}
	if len(result.Server.ServerCompileTimeCaps) <= 27 || result.Server.ServerCompileTimeCaps[27] == 0 {
		result.CompileTimeCaps[27] = 0
	}
	xmlTypeClientSideDecoding := false
	if len(result.Server.ServerCompileTimeCaps) > 7 {
		if result.Server.ServerCompileTimeCaps[7] >= 8 && xmlTypeClientSideDecoding {
			result.CompileTimeCaps[36] = 4
		} else if result.Server.ServerCompileTimeCaps[7] < 7 {
			result.CompileTimeCaps[36] = 0
		}
	}
	if len(result.Server.ServerRuntimeCaps) < 1 || result.Server.ServerRuntimeCaps[1]&1 != 1 {
		result.RuntimeCap[1] &= 0
	}
	if len(result.Server.ServerRuntimeCaps) > 6 {
		if result.Server.ServerRuntimeCaps[6]&4 == 4 {
			result.RuntimeCap[6] |= 4
			result.b32kTypeSupported = true
		}
		if result.Server.ServerRuntimeCaps[6]&16 == 16 {
			result.supportSessionStateOps = true
		}
		if result.Server.ServerRuntimeCaps[6]&2 == 2 {
			result.RuntimeCap[6] |= 2
		}
	}
	if len(result.Server.ServerCompileTimeCaps) <= 37 || result.Server.ServerCompileTimeCaps[37]&2 != 2 {
		result.CompileTimeCaps[37] = 0
		result.CompileTimeCaps[1] = 0
	}

	result.TypeAndRep[0] = 1
	result.addTypeRep(int16(NCHAR), int16(NCHAR), TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(int16(NUMBER), int16(NUMBER), TNS_TYPE_REP_ORACLE)
	result.addTypeRep(int16(LONG), int16(LONG), TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(int16(DATE), int16(DATE), TNS_TYPE_REP_ORACLE)
	result.addTypeRep(int16(RAW), int16(RAW), TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(int16(LongRaw), int16(LongRaw), TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(TNS_DATA_TYPE_UB2, TNS_DATA_TYPE_UB2, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(TNS_DATA_TYPE_UB4, TNS_DATA_TYPE_UB4, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(TNS_DATA_TYPE_SB1, TNS_DATA_TYPE_SB1, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(TNS_DATA_TYPE_SB2, TNS_DATA_TYPE_SB2, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(TNS_DATA_TYPE_SB4, TNS_DATA_TYPE_SB4, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(TNS_DATA_TYPE_SWORD, TNS_DATA_TYPE_SWORD, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(TNS_DATA_TYPE_UWORD, TNS_DATA_TYPE_UWORD, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(TNS_DATA_TYPE_PTRB, TNS_DATA_TYPE_PTRB, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(TNS_DATA_TYPE_PTRW, TNS_DATA_TYPE_PTRW, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(TNS_DATA_TYPE_TIDDEF, TNS_DATA_TYPE_TIDDEF, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(int16(ROWID), int16(ROWID), TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(40, 40, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(41, 41, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(117, 117, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(120, 120, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(290, 290, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(291, 291, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(292, 292, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(293, 293, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(294, 294, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(298, 298, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(299, 299, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(300, 300, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(301, 301, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(302, 302, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(303, 303, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(304, 304, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(305, 305, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(306, 306, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(307, 307, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(308, 308, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(309, 309, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(310, 310, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(311, 311, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(312, 312, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(313, 313, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(315, 315, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(316, 316, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(317, 317, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(318, 318, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(319, 319, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(320, 320, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(321, 321, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(322, 322, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(323, 323, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(327, 327, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(328, 328, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(329, 329, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(331, 331, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(333, 333, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(334, 334, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(335, 335, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(336, 336, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(337, 337, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(338, 338, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(339, 339, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(340, 340, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(341, 341, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(342, 342, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(343, 343, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(344, 344, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(345, 345, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(346, 346, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(348, 348, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(349, 349, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(354, 354, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(355, 355, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(359, 359, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(363, 363, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(380, 380, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(381, 381, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(382, 382, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(383, 383, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(384, 384, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(385, 385, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(386, 386, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(387, 387, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(388, 388, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(389, 389, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(390, 390, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(391, 391, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(393, 393, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(394, 394, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(395, 395, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(396, 396, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(397, 397, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(398, 398, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(399, 399, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(400, 400, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(401, 401, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(404, 404, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(405, 405, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(406, 406, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(407, 407, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(413, 413, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(414, 414, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(415, 415, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(416, 416, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(417, 417, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(418, 418, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(419, 419, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(420, 420, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(421, 421, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(422, 422, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(423, 423, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(424, 424, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(425, 425, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(426, 426, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(427, 427, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(429, 429, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(430, 430, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(431, 431, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(432, 432, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(433, 433, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(449, 449, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(450, 450, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(454, 454, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(455, 455, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(456, 456, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(457, 457, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(458, 458, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(459, 459, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(460, 460, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(461, 461, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(462, 462, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(463, 463, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(466, 466, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(467, 467, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(468, 468, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(469, 469, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(470, 470, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(471, 471, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(472, 472, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(473, 473, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(474, 474, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(475, 475, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(476, 476, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(477, 477, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(478, 478, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(479, 479, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(480, 480, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(481, 481, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(482, 482, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(483, 483, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(484, 484, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(485, 485, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(486, 486, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(490, 490, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(491, 491, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(492, 492, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(493, 493, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(494, 494, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(495, 495, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(496, 496, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(498, 498, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(499, 499, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(500, 500, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(501, 501, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(502, 502, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(509, 509, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(510, 510, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(513, 513, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(514, 514, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(516, 516, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(517, 517, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(518, 518, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(519, 519, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(520, 520, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(521, 521, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(522, 522, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(523, 523, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(524, 524, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(525, 525, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(526, 526, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(527, 527, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(528, 528, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(529, 529, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(530, 530, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(531, 531, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(532, 532, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(533, 533, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(534, 534, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(535, 535, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(536, 536, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(537, 537, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(538, 538, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(539, 539, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(540, 540, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(541, 541, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(542, 542, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(543, 543, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(560, 560, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(565, 565, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(572, 572, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(573, 573, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(574, 574, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(575, 575, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(576, 576, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(578, 578, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(563, 563, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(564, 564, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(579, 579, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(580, 580, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(581, 581, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(582, 582, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(583, 583, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(584, 584, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(585, 585, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(3, 2, TNS_TYPE_REP_ORACLE)
	result.addTypeRep(4, 2, TNS_TYPE_REP_ORACLE)
	result.addTypeRep(5, 1, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(6, 2, TNS_TYPE_REP_ORACLE)
	result.addTypeRep(7, 2, TNS_TYPE_REP_ORACLE)
	result.addTypeRep(9, 1, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(13, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(14, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(15, 23, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(16, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(17, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(18, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(19, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(20, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(21, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(22, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(39, 120, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(58, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(68, 2, TNS_TYPE_REP_ORACLE)
	result.addTypeRep(69, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(70, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(74, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(76, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(91, 2, TNS_TYPE_REP_ORACLE)
	result.addTypeRep(94, 1, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(95, 23, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(96, 96, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(97, 96, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(100, 100, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(101, 101, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(102, 102, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(104, 11, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(105, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(106, 106, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(108, 109, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(109, 109, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(110, 111, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(111, 111, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(112, 112, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(113, 113, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(114, 114, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(115, 115, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(116, 102, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(118, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(119, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(121, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(122, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(123, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(136, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(146, 146, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(147, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(152, 2, TNS_TYPE_REP_ORACLE)
	result.addTypeRep(153, 2, TNS_TYPE_REP_ORACLE)
	result.addTypeRep(154, 2, TNS_TYPE_REP_ORACLE)
	result.addTypeRep(155, 1, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(156, 12, TNS_TYPE_REP_ORACLE)
	result.addTypeRep(172, 2, TNS_TYPE_REP_ORACLE)
	result.addTypeRep(178, 178, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(179, 179, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(180, 180, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(181, 181, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(182, 182, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(183, 183, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(184, 12, TNS_TYPE_REP_ORACLE)
	result.addTypeRep(185, 185, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(186, 186, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(187, 187, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(188, 188, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(189, 189, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(190, 190, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(191, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(192, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(195, 112, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(196, 113, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(197, 114, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(208, 208, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(209, 0, TNS_TYPE_REP_NATIVE)
	result.addTypeRep(231, 231, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(232, 231, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(233, 233, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(252, 252, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(241, 109, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(515, 0, TNS_TYPE_REP_NATIVE)

	result.DataTypeRepFor1100 = result.TypeAndRep[0]
	result.addTypeRep(590, 590, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(591, 591, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(592, 592, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(613, 613, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(614, 614, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(615, 615, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(616, 616, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(611, 611, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(612, 612, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(593, 593, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(594, 594, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(595, 595, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(596, 596, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(597, 597, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(598, 598, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(599, 599, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(600, 600, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(601, 601, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(602, 602, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(603, 603, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(604, 604, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(605, 605, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(622, 622, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(623, 623, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(624, 624, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(625, 625, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(626, 626, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(627, 627, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(628, 628, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(629, 629, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(630, 630, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(631, 631, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(632, 632, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(637, 637, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(638, 638, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(636, 636, TNS_TYPE_REP_UNIVERSAL)
	result.DataTypeRepFor1200 = result.TypeAndRep[0]
	result.addTypeRep(639, 639, TNS_TYPE_REP_UNIVERSAL)
	result.addTypeRep(640, 640, TNS_TYPE_REP_UNIVERSAL)
	if result.Server.ServerCompileTimeCaps[7] >= 8 {
		result.RuntimeTypeAndRep = result.TypeAndRep
	} else if result.Server.ServerCompileTimeCaps[7] >= 7 {
		result.RuntimeTypeAndRep = result.TypeAndRep[:result.DataTypeRepFor1200]
	} else {
		result.RuntimeTypeAndRep = result.TypeAndRep[:result.DataTypeRepFor1100]
	}
	return &result
}
func (nego *DataTypeNego) read(session *network.Session) error {
	msg, err := session.GetByte()
	if err != nil {
		return err
	}
	if msg != 2 {
		return errors.New(fmt.Sprintf("message code error: received code %d and expected code is 2", msg))
	}
	if nego.RuntimeCap[1] == 1 {
		nego.DBTimeZone, err = session.GetBytes(11)
		if err != nil {
			return err
		}
		if nego.CompileTimeCaps[37]&2 == 2 {
			nego.serverTZVersion, _ = session.GetInt(4, false, true)
		}
	}
	level := 0
	for {
		var num int
		if nego.CompileTimeCaps[27] == 0 {
			num, err = session.GetInt(1, false, false)
		} else {
			num, err = session.GetInt(2, false, true)
		}
		if num == 0 && level == 0 {
			break
		}
		if num == 0 && level == 1 {
			level = 0
			continue
		}
		if level == 3 {
			level = 0
			continue
		}
		level++
	}

	return nil
}
func (nego *DataTypeNego) write(session *network.Session) error {
	session.ResetBuffer()
	if nego.Server.ServerCompileTimeCaps == nil || len(nego.Server.ServerCompileTimeCaps) <= 27 || nego.Server.ServerCompileTimeCaps[27] == 0 {
		nego.CompileTimeCaps[27] = 0
	}
	session.PutBytes(nego.MessageCode)
	// client remote in
	//session.PutBytes(0, 0, 0, 0)
	session.PutInt(nego.Server.ServerCharset, 2, false, false)
	// client remote out
	session.PutInt(nego.Server.ServerCharset, 2, false, false)
	session.PutBytes(nego.Server.ServerFlags, uint8(len(nego.CompileTimeCaps)))
	session.PutBytes(nego.CompileTimeCaps...)
	session.PutBytes(uint8(len(nego.RuntimeCap)))
	session.PutBytes(nego.RuntimeCap...)
	if nego.RuntimeCap[1]&1 == 1 {
		session.PutBytes(TZBytes()...)
		if nego.CompileTimeCaps[37]&2 == 2 {
			session.PutInt(nego.clientTZVersion, 4, true, false)
			//session.PutBytes(0, 0, 0, uint8(nego.clientTZVersion))
		}
	}
	session.PutInt(nego.Server.ServernCharset, 2, false, false)
	// marshal type reps
	size := nego.RuntimeTypeAndRep[0]
	if nego.CompileTimeCaps[27] == 0 {
		for _, x := range nego.RuntimeTypeAndRep[1:size] {
			session.PutBytes(uint8(x))
		}
		session.PutBytes(0)
	} else {
		for _, x := range nego.RuntimeTypeAndRep[1:size] {
			session.PutInt(x, 2, true, false)
		}
		session.PutBytes(0, 0)
	}
	return session.Write()
}

func TZBytes() []byte {
	_, offset := time.Now().Zone()
	hours := int8(offset / 3600)
	minutes := int8((offset / 60) % 60)
	seconds := int8(offset % 60)
	return []byte{128, 0, 0, 0, uint8(hours + 60), uint8(minutes + 60), uint8(seconds + 60), 128, 0, 0, 0}
}
