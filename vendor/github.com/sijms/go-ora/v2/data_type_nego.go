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
}

const bufferGrow int = 2369

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
		RuntimeCap:             []byte{2, 1, 0, 0, 0, 0, 0},
		b32kTypeSupported:      false,
		supportSessionStateOps: false,
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
	result.addTypeRep(1, 1, 1)
	result.addTypeRep(2, 2, 10)
	result.addTypeRep(8, 8, 1)
	result.addTypeRep(12, 12, 10)
	result.addTypeRep(23, 23, 1)
	result.addTypeRep(24, 24, 1)
	result.addTypeRep(25, 25, 1)
	result.addTypeRep(26, 26, 1)
	result.addTypeRep(27, 27, 1)
	result.addTypeRep(28, 28, 1)
	result.addTypeRep(29, 29, 1)
	result.addTypeRep(30, 30, 1)
	result.addTypeRep(31, 31, 1)
	result.addTypeRep(32, 32, 1)
	result.addTypeRep(33, 33, 1)
	result.addTypeRep(10, 10, 1)
	result.addTypeRep(11, 11, 1)
	result.addTypeRep(40, 40, 1)
	result.addTypeRep(41, 41, 1)
	result.addTypeRep(117, 117, 1)
	result.addTypeRep(120, 120, 1)
	result.addTypeRep(290, 290, 1)
	result.addTypeRep(291, 291, 1)
	result.addTypeRep(292, 292, 1)
	result.addTypeRep(293, 293, 1)
	result.addTypeRep(294, 294, 1)
	result.addTypeRep(298, 298, 1)
	result.addTypeRep(299, 299, 1)
	result.addTypeRep(300, 300, 1)
	result.addTypeRep(301, 301, 1)
	result.addTypeRep(302, 302, 1)
	result.addTypeRep(303, 303, 1)
	result.addTypeRep(304, 304, 1)
	result.addTypeRep(305, 305, 1)
	result.addTypeRep(306, 306, 1)
	result.addTypeRep(307, 307, 1)
	result.addTypeRep(308, 308, 1)
	result.addTypeRep(309, 309, 1)
	result.addTypeRep(310, 310, 1)
	result.addTypeRep(311, 311, 1)
	result.addTypeRep(312, 312, 1)
	result.addTypeRep(313, 313, 1)
	result.addTypeRep(315, 315, 1)
	result.addTypeRep(316, 316, 1)
	result.addTypeRep(317, 317, 1)
	result.addTypeRep(318, 318, 1)
	result.addTypeRep(319, 319, 1)
	result.addTypeRep(320, 320, 1)
	result.addTypeRep(321, 321, 1)
	result.addTypeRep(322, 322, 1)
	result.addTypeRep(323, 323, 1)
	result.addTypeRep(327, 327, 1)
	result.addTypeRep(328, 328, 1)
	result.addTypeRep(329, 329, 1)
	result.addTypeRep(331, 331, 1)
	result.addTypeRep(333, 333, 1)
	result.addTypeRep(334, 334, 1)
	result.addTypeRep(335, 335, 1)
	result.addTypeRep(336, 336, 1)
	result.addTypeRep(337, 337, 1)
	result.addTypeRep(338, 338, 1)
	result.addTypeRep(339, 339, 1)
	result.addTypeRep(340, 340, 1)
	result.addTypeRep(341, 341, 1)
	result.addTypeRep(342, 342, 1)
	result.addTypeRep(343, 343, 1)
	result.addTypeRep(344, 344, 1)
	result.addTypeRep(345, 345, 1)
	result.addTypeRep(346, 346, 1)
	result.addTypeRep(348, 348, 1)
	result.addTypeRep(349, 349, 1)
	result.addTypeRep(354, 354, 1)
	result.addTypeRep(355, 355, 1)
	result.addTypeRep(359, 359, 1)
	result.addTypeRep(363, 363, 1)
	result.addTypeRep(380, 380, 1)
	result.addTypeRep(381, 381, 1)
	result.addTypeRep(382, 382, 1)
	result.addTypeRep(383, 383, 1)
	result.addTypeRep(384, 384, 1)
	result.addTypeRep(385, 385, 1)
	result.addTypeRep(386, 386, 1)
	result.addTypeRep(387, 387, 1)
	result.addTypeRep(388, 388, 1)
	result.addTypeRep(389, 389, 1)
	result.addTypeRep(390, 390, 1)
	result.addTypeRep(391, 391, 1)
	result.addTypeRep(393, 393, 1)
	result.addTypeRep(394, 394, 1)
	result.addTypeRep(395, 395, 1)
	result.addTypeRep(396, 396, 1)
	result.addTypeRep(397, 397, 1)
	result.addTypeRep(398, 398, 1)
	result.addTypeRep(399, 399, 1)
	result.addTypeRep(400, 400, 1)
	result.addTypeRep(401, 401, 1)
	result.addTypeRep(404, 404, 1)
	result.addTypeRep(405, 405, 1)
	result.addTypeRep(406, 406, 1)
	result.addTypeRep(407, 407, 1)
	result.addTypeRep(413, 413, 1)
	result.addTypeRep(414, 414, 1)
	result.addTypeRep(415, 415, 1)
	result.addTypeRep(416, 416, 1)
	result.addTypeRep(417, 417, 1)
	result.addTypeRep(418, 418, 1)
	result.addTypeRep(419, 419, 1)
	result.addTypeRep(420, 420, 1)
	result.addTypeRep(421, 421, 1)
	result.addTypeRep(422, 422, 1)
	result.addTypeRep(423, 423, 1)
	result.addTypeRep(424, 424, 1)
	result.addTypeRep(425, 425, 1)
	result.addTypeRep(426, 426, 1)
	result.addTypeRep(427, 427, 1)
	result.addTypeRep(429, 429, 1)
	result.addTypeRep(430, 430, 1)
	result.addTypeRep(431, 431, 1)
	result.addTypeRep(432, 432, 1)
	result.addTypeRep(433, 433, 1)
	result.addTypeRep(449, 449, 1)
	result.addTypeRep(450, 450, 1)
	result.addTypeRep(454, 454, 1)
	result.addTypeRep(455, 455, 1)
	result.addTypeRep(456, 456, 1)
	result.addTypeRep(457, 457, 1)
	result.addTypeRep(458, 458, 1)
	result.addTypeRep(459, 459, 1)
	result.addTypeRep(460, 460, 1)
	result.addTypeRep(461, 461, 1)
	result.addTypeRep(462, 462, 1)
	result.addTypeRep(463, 463, 1)
	result.addTypeRep(466, 466, 1)
	result.addTypeRep(467, 467, 1)
	result.addTypeRep(468, 468, 1)
	result.addTypeRep(469, 469, 1)
	result.addTypeRep(470, 470, 1)
	result.addTypeRep(471, 471, 1)
	result.addTypeRep(472, 472, 1)
	result.addTypeRep(473, 473, 1)
	result.addTypeRep(474, 474, 1)
	result.addTypeRep(475, 475, 1)
	result.addTypeRep(476, 476, 1)
	result.addTypeRep(477, 477, 1)
	result.addTypeRep(478, 478, 1)
	result.addTypeRep(479, 479, 1)
	result.addTypeRep(480, 480, 1)
	result.addTypeRep(481, 481, 1)
	result.addTypeRep(482, 482, 1)
	result.addTypeRep(483, 483, 1)
	result.addTypeRep(484, 484, 1)
	result.addTypeRep(485, 485, 1)
	result.addTypeRep(486, 486, 1)
	result.addTypeRep(490, 490, 1)
	result.addTypeRep(491, 491, 1)
	result.addTypeRep(492, 492, 1)
	result.addTypeRep(493, 493, 1)
	result.addTypeRep(494, 494, 1)
	result.addTypeRep(495, 495, 1)
	result.addTypeRep(496, 496, 1)
	result.addTypeRep(498, 498, 1)
	result.addTypeRep(499, 499, 1)
	result.addTypeRep(500, 500, 1)
	result.addTypeRep(501, 501, 1)
	result.addTypeRep(502, 502, 1)
	result.addTypeRep(509, 509, 1)
	result.addTypeRep(510, 510, 1)
	result.addTypeRep(513, 513, 1)
	result.addTypeRep(514, 514, 1)
	result.addTypeRep(516, 516, 1)
	result.addTypeRep(517, 517, 1)
	result.addTypeRep(518, 518, 1)
	result.addTypeRep(519, 519, 1)
	result.addTypeRep(520, 520, 1)
	result.addTypeRep(521, 521, 1)
	result.addTypeRep(522, 522, 1)
	result.addTypeRep(523, 523, 1)
	result.addTypeRep(524, 524, 1)
	result.addTypeRep(525, 525, 1)
	result.addTypeRep(526, 526, 1)
	result.addTypeRep(527, 527, 1)
	result.addTypeRep(528, 528, 1)
	result.addTypeRep(529, 529, 1)
	result.addTypeRep(530, 530, 1)
	result.addTypeRep(531, 531, 1)
	result.addTypeRep(532, 532, 1)
	result.addTypeRep(533, 533, 1)
	result.addTypeRep(534, 534, 1)
	result.addTypeRep(535, 535, 1)
	result.addTypeRep(536, 536, 1)
	result.addTypeRep(537, 537, 1)
	result.addTypeRep(538, 538, 1)
	result.addTypeRep(539, 539, 1)
	result.addTypeRep(540, 540, 1)
	result.addTypeRep(541, 541, 1)
	result.addTypeRep(542, 542, 1)
	result.addTypeRep(543, 543, 1)
	result.addTypeRep(560, 560, 1)
	result.addTypeRep(565, 565, 1)
	result.addTypeRep(572, 572, 1)
	result.addTypeRep(573, 573, 1)
	result.addTypeRep(574, 574, 1)
	result.addTypeRep(575, 575, 1)
	result.addTypeRep(576, 576, 1)
	result.addTypeRep(578, 578, 1)
	result.addTypeRep(563, 563, 1)
	result.addTypeRep(564, 564, 1)
	result.addTypeRep(579, 579, 1)
	result.addTypeRep(580, 580, 1)
	result.addTypeRep(581, 581, 1)
	result.addTypeRep(582, 582, 1)
	result.addTypeRep(583, 583, 1)
	result.addTypeRep(584, 584, 1)
	result.addTypeRep(585, 585, 1)
	result.addTypeRep(3, 2, 10)
	result.addTypeRep(4, 2, 10)
	result.addTypeRep(5, 1, 1)
	result.addTypeRep(6, 2, 10)
	result.addTypeRep(7, 2, 10)
	result.addTypeRep(9, 1, 1)
	result.addTypeRep(13, 0, 0)
	result.addTypeRep(14, 0, 0)
	result.addTypeRep(15, 23, 1)
	result.addTypeRep(16, 0, 0)
	result.addTypeRep(17, 0, 0)
	result.addTypeRep(18, 0, 0)
	result.addTypeRep(19, 0, 0)
	result.addTypeRep(20, 0, 0)
	result.addTypeRep(21, 0, 0)
	result.addTypeRep(22, 0, 0)
	result.addTypeRep(39, 120, 1)
	result.addTypeRep(58, 0, 0)
	result.addTypeRep(68, 2, 10)
	result.addTypeRep(69, 0, 0)
	result.addTypeRep(70, 0, 0)
	result.addTypeRep(74, 0, 0)
	result.addTypeRep(76, 0, 0)
	result.addTypeRep(91, 2, 10)
	result.addTypeRep(94, 1, 1)
	result.addTypeRep(95, 23, 1)
	result.addTypeRep(96, 96, 1)
	result.addTypeRep(97, 96, 1)
	result.addTypeRep(100, 100, 1)
	result.addTypeRep(101, 101, 1)
	result.addTypeRep(102, 102, 1)
	result.addTypeRep(104, 11, 1)
	result.addTypeRep(105, 0, 0)
	result.addTypeRep(106, 106, 1)
	result.addTypeRep(108, 109, 1)
	result.addTypeRep(109, 109, 1)
	result.addTypeRep(110, 111, 1)
	result.addTypeRep(111, 111, 1)
	result.addTypeRep(112, 112, 1)
	result.addTypeRep(113, 113, 1)
	result.addTypeRep(114, 114, 1)
	result.addTypeRep(115, 115, 1)
	result.addTypeRep(116, 102, 1)
	result.addTypeRep(118, 0, 0)
	result.addTypeRep(119, 0, 0)
	result.addTypeRep(121, 0, 0)
	result.addTypeRep(122, 0, 0)
	result.addTypeRep(123, 0, 0)
	result.addTypeRep(136, 0, 0)
	result.addTypeRep(146, 146, 1)
	result.addTypeRep(147, 0, 0)
	result.addTypeRep(152, 2, 10)
	result.addTypeRep(153, 2, 10)
	result.addTypeRep(154, 2, 10)
	result.addTypeRep(155, 1, 1)
	result.addTypeRep(156, 12, 10)
	result.addTypeRep(172, 2, 10)
	result.addTypeRep(178, 178, 1)
	result.addTypeRep(179, 179, 1)
	result.addTypeRep(180, 180, 1)
	result.addTypeRep(181, 181, 1)
	result.addTypeRep(182, 182, 1)
	result.addTypeRep(183, 183, 1)
	result.addTypeRep(184, 12, 10)
	result.addTypeRep(185, 185, 1)
	result.addTypeRep(186, 186, 1)
	result.addTypeRep(187, 187, 1)
	result.addTypeRep(188, 188, 1)
	result.addTypeRep(189, 189, 1)
	result.addTypeRep(190, 190, 1)
	result.addTypeRep(191, 0, 0)
	result.addTypeRep(192, 0, 0)
	result.addTypeRep(195, 112, 1)
	result.addTypeRep(196, 113, 1)
	result.addTypeRep(197, 114, 1)
	result.addTypeRep(208, 208, 1)
	result.addTypeRep(209, 0, 0)
	result.addTypeRep(231, 231, 1)
	result.addTypeRep(232, 231, 1)
	result.addTypeRep(233, 233, 1)
	result.addTypeRep(252, 252, 1)
	result.addTypeRep(241, 109, 1)
	result.addTypeRep(515, 0, 0)

	result.DataTypeRepFor1100 = result.TypeAndRep[0]
	result.addTypeRep(590, 590, 1)
	result.addTypeRep(591, 591, 1)
	result.addTypeRep(592, 592, 1)
	result.addTypeRep(613, 613, 1)
	result.addTypeRep(614, 614, 1)
	result.addTypeRep(615, 615, 1)
	result.addTypeRep(616, 616, 1)
	result.addTypeRep(611, 611, 1)
	result.addTypeRep(612, 612, 1)
	result.addTypeRep(593, 593, 1)
	result.addTypeRep(594, 594, 1)
	result.addTypeRep(595, 595, 1)
	result.addTypeRep(596, 596, 1)
	result.addTypeRep(597, 597, 1)
	result.addTypeRep(598, 598, 1)
	result.addTypeRep(599, 599, 1)
	result.addTypeRep(600, 600, 1)
	result.addTypeRep(601, 601, 1)
	result.addTypeRep(602, 602, 1)
	result.addTypeRep(603, 603, 1)
	result.addTypeRep(604, 604, 1)
	result.addTypeRep(605, 605, 1)
	result.addTypeRep(622, 622, 1)
	result.addTypeRep(623, 623, 1)
	result.addTypeRep(624, 624, 1)
	result.addTypeRep(625, 625, 1)
	result.addTypeRep(626, 626, 1)
	result.addTypeRep(627, 627, 1)
	result.addTypeRep(628, 628, 1)
	result.addTypeRep(629, 629, 1)
	result.addTypeRep(630, 630, 1)
	result.addTypeRep(631, 631, 1)
	result.addTypeRep(632, 632, 1)
	result.addTypeRep(637, 637, 1)
	result.addTypeRep(638, 638, 1)
	result.addTypeRep(636, 636, 1)
	result.DataTypeRepFor1200 = result.TypeAndRep[0]
	result.addTypeRep(639, 639, 1)
	result.addTypeRep(640, 640, 1)
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
			_, _ = session.GetInt(4, false, false)
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
			session.PutBytes(0, 0, 0, 21)
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
