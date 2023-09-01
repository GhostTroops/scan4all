package converters

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"strconv"
	"strings"
	"time"
)

const (
	maxConvertibleInt    = (1 << 63) - 1
	maxConvertibleNegInt = (1 << 63)
)

var oracleZones = map[int]string{
	42:   "Africa/Abidjan",
	50:   "Africa/Accra",
	47:   "Africa/Addis_Ababa",
	30:   "Africa/Algiers",
	46:   "Africa/Asmara",
	558:  "Africa/Asmera",
	58:   "Africa/Bamako",
	37:   "Africa/Bangui",
	49:   "Africa/Banjul",
	52:   "Africa/Bissau",
	57:   "Africa/Blantyre",
	41:   "Africa/Brazzaville",
	35:   "Africa/Bujumbura",
	44:   "Africa/Cairo",
	61:   "Africa/Casablanca",
	81:   "Africa/Ceuta",
	51:   "Africa/Conakry",
	69:   "Africa/Dakar",
	75:   "Africa/Dar_es_Salaam",
	43:   "Africa/Djibouti",
	36:   "Africa/Douala",
	62:   "Africa/El_Aaiun",
	70:   "Africa/Freetown",
	33:   "Africa/Gaborone",
	80:   "Africa/Harare",
	72:   "Africa/Johannesburg",
	321:  "Africa/Juba",
	78:   "Africa/Kampala",
	73:   "Africa/Khartoum",
	67:   "Africa/Kigali",
	39:   "Africa/Kinshasa",
	66:   "Africa/Lagos",
	48:   "Africa/Libreville",
	76:   "Africa/Lome",
	31:   "Africa/Luanda",
	40:   "Africa/Lubumbashi",
	79:   "Africa/Lusaka",
	45:   "Africa/Malabo",
	63:   "Africa/Maputo",
	54:   "Africa/Maseru",
	74:   "Africa/Mbabane",
	71:   "Africa/Mogadishu",
	55:   "Africa/Monrovia",
	53:   "Africa/Nairobi",
	38:   "Africa/Ndjamena",
	65:   "Africa/Niamey",
	60:   "Africa/Nouakchott",
	34:   "Africa/Ouagadougou",
	32:   "Africa/Porto-Novo",
	68:   "Africa/Sao_Tome",
	570:  "Africa/Timbuktu",
	56:   "Africa/Tripoli",
	77:   "Africa/Tunis",
	64:   "Africa/Windhoek",
	108:  "America/Adak",
	106:  "America/Anchorage",
	146:  "America/Anguilla",
	147:  "America/Antigua",
	186:  "America/Araguaina",
	687:  "America/Argentina/Buenos_Aires",
	691:  "America/Argentina/Catamarca",
	1203: "America/Argentina/ComodRivadavia",
	689:  "America/Argentina/Cordoba",
	690:  "America/Argentina/Jujuy",
	99:   "America/Argentina/La_Rioja",
	692:  "America/Argentina/Mendoza",
	98:   "America/Argentina/Rio_Gallegos",
	237:  "America/Argentina/Salta",
	229:  "America/Argentina/San_Juan",
	97:   "America/Argentina/San_Luis",
	228:  "America/Argentina/Tucuman",
	176:  "America/Argentina/Ushuaia",
	181:  "America/Aruba",
	200:  "America/Asuncion",
	221:  "America/Atikokan",
	620:  "America/Atka",
	90:   "America/Bahia",
	95:   "America/Bahia_Banderas",
	149:  "America/Barbados",
	184:  "America/Belem",
	150:  "America/Belize",
	224:  "America/Blanc-Sablon",
	191:  "America/Boa_Vista",
	195:  "America/Bogota",
	110:  "America/Boise",
	175:  "America/Buenos_Aires",
	135:  "America/Cambridge_Bay",
	222:  "America/Campo_Grande",
	140:  "America/Cancun",
	205:  "America/Caracas",
	179:  "America/Catamarca",
	198:  "America/Cayenne",
	151:  "America/Cayman",
	101:  "America/Chicago",
	142:  "America/Chihuahua",
	733:  "America/Coral_Harbour",
	177:  "America/Cordoba",
	152:  "America/Costa_Rica",
	325:  "America/Creston",
	189:  "America/Cuiaba",
	196:  "America/Curacao",
	223:  "America/Danmarkshavn",
	139:  "America/Dawson",
	131:  "America/Dawson_Creek",
	102:  "America/Denver",
	116:  "America/Detroit",
	154:  "America/Dominica",
	129:  "America/Edmonton",
	225:  "America/Eirunepe",
	156:  "America/El_Salvador",
	657:  "America/Ensenada",
	343:  "America/Fort_Nelson",
	623:  "America/Fort_Wayne",
	185:  "America/Fortaleza",
	121:  "America/Glace_Bay",
	207:  "America/Godthab",
	119:  "America/Goose_Bay",
	172:  "America/Grand_Turk",
	157:  "America/Grenada",
	158:  "America/Guadeloupe",
	159:  "America/Guatemala",
	197:  "America/Guayaquil",
	199:  "America/Guyana",
	120:  "America/Halifax",
	153:  "America/Havana",
	143:  "America/Hermosillo",
	1647: "America/Indiana/Indianapolis",
	113:  "America/Indiana/Knox",
	112:  "America/Indiana/Marengo",
	210:  "America/Indiana/Petersburg",
	94:   "America/Indiana/Tell_City",
	114:  "America/Indiana/Vevay",
	209:  "America/Indiana/Vincennes",
	218:  "America/Indiana/Winamac",
	111:  "America/Indianapolis",
	137:  "America/Inuvik",
	133:  "America/Iqaluit",
	162:  "America/Jamaica",
	178:  "America/Jujuy",
	104:  "America/Juneau",
	627:  "America/Kentucky/Louisville",
	91:   "America/Kentucky/Monticello",
	625:  "America/Knox_IN",
	323:  "America/Kralendijk",
	182:  "America/La_Paz",
	201:  "America/Lima",
	103:  "America/Los_Angeles",
	115:  "America/Louisville",
	322:  "America/Lower_Princes",
	187:  "America/Maceio",
	165:  "America/Managua",
	192:  "America/Manaus",
	670:  "America/Marigot",
	163:  "America/Martinique",
	87:   "America/Matamoros",
	144:  "America/Mazatlan",
	180:  "America/Mendoza",
	117:  "America/Menominee",
	226:  "America/Merida",
	319:  "America/Metlakatla",
	141:  "America/Mexico_City",
	170:  "America/Miquelon",
	92:   "America/Moncton",
	227:  "America/Monterrey",
	204:  "America/Montevideo",
	122:  "America/Montreal",
	164:  "America/Montserrat",
	148:  "America/Nassau",
	100:  "America/New_York",
	124:  "America/Nipigon",
	107:  "America/Nome",
	183:  "America/Noronha",
	320:  "America/North_Dakota/Beulah",
	88:   "America/North_Dakota/Center",
	89:   "America/North_Dakota/New_Salem",
	93:   "America/Ojinaga",
	166:  "America/Panama",
	132:  "America/Pangnirtung",
	202:  "America/Paramaribo",
	109:  "America/Phoenix",
	160:  "America/Port-au-Prince",
	203:  "America/Port_of_Spain",
	193:  "America/Porto_Acre",
	190:  "America/Porto_Velho",
	167:  "America/Puerto_Rico",
	394:  "America/Punta_Arenas",
	125:  "America/Rainy_River",
	134:  "America/Rankin_Inlet",
	86:   "America/Recife",
	127:  "America/Regina",
	219:  "America/Resolute",
	1217: "America/Rio_Branco",
	1201: "America/Rosario",
	96:   "America/Santa_Isabel",
	83:   "America/Santarem",
	194:  "America/Santiago",
	155:  "America/Santo_Domingo",
	188:  "America/Sao_Paulo",
	206:  "America/Scoresbysund",
	1638: "America/Shiprock",
	318:  "America/Sitka",
	1182: "America/St_Barthelemy",
	118:  "America/St_Johns",
	168:  "America/St_Kitts",
	169:  "America/St_Lucia",
	174:  "America/St_Thomas",
	171:  "America/St_Vincent",
	128:  "America/Swift_Current",
	161:  "America/Tegucigalpa",
	208:  "America/Thule",
	123:  "America/Thunder_Bay",
	145:  "America/Tijuana",
	220:  "America/Toronto",
	173:  "America/Tortola",
	130:  "America/Vancouver",
	686:  "America/Virgin",
	138:  "America/Whitehorse",
	126:  "America/Winnipeg",
	105:  "America/Yakutat",
	136:  "America/Yellowknife",
	230:  "Antarctica/Casey",
	231:  "Antarctica/Davis",
	233:  "Antarctica/DumontDUrville",
	85:   "Antarctica/Macquarie",
	232:  "Antarctica/Mawson",
	236:  "Antarctica/McMurdo",
	235:  "Antarctica/Palmer",
	82:   "Antarctica/Rothera",
	748:  "Antarctica/South_Pole",
	234:  "Antarctica/Syowa",
	329:  "Antarctica/Troll",
	59:   "Antarctica/Vostok",
	909:  "Arctic/Longyearbyen",
	302:  "Asia/Aden",
	269:  "Asia/Almaty",
	268:  "Asia/Amman",
	312:  "Asia/Anadyr",
	271:  "Asia/Aqtau",
	270:  "Asia/Aqtobe",
	297:  "Asia/Ashgabat",
	809:  "Asia/Ashkhabad",
	363:  "Asia/Atyrau",
	265:  "Asia/Baghdad",
	243:  "Asia/Bahrain",
	242:  "Asia/Baku",
	296:  "Asia/Bangkok",
	359:  "Asia/Barnaul",
	277:  "Asia/Beirut",
	272:  "Asia/Bishkek",
	246:  "Asia/Brunei",
	260:  "Asia/Calcutta",
	335:  "Asia/Chita",
	316:  "Asia/Choibalsan",
	763:  "Asia/Chongqing",
	251:  "Asia/Chungking",
	293:  "Asia/Colombo",
	244:  "Asia/Dacca",
	294:  "Asia/Damascus",
	756:  "Asia/Dhaka",
	259:  "Asia/Dili",
	298:  "Asia/Dubai",
	295:  "Asia/Dushanbe",
	362:  "Asia/Famagusta",
	285:  "Asia/Gaza",
	249:  "Asia/Harbin",
	324:  "Asia/Hebron",
	813:  "Asia/Ho_Chi_Minh",
	254:  "Asia/Hong_Kong",
	280:  "Asia/Hovd",
	307:  "Asia/Irkutsk",
	1431: "Asia/Istanbul",
	261:  "Asia/Jakarta",
	263:  "Asia/Jayapura",
	266:  "Asia/Jerusalem",
	240:  "Asia/Kabul",
	311:  "Asia/Kamchatka",
	284:  "Asia/Karachi",
	253:  "Asia/Kashgar",
	797:  "Asia/Kathmandu",
	282:  "Asia/Katmandu",
	326:  "Asia/Khandyga",
	772:  "Asia/Kolkata",
	306:  "Asia/Krasnoyarsk",
	278:  "Asia/Kuala_Lumpur",
	279:  "Asia/Kuching",
	275:  "Asia/Kuwait",
	256:  "Asia/Macao",
	768:  "Asia/Macau",
	310:  "Asia/Magadan",
	774:  "Asia/Makassar",
	286:  "Asia/Manila",
	283:  "Asia/Muscat",
	257:  "Asia/Nicosia",
	84:   "Asia/Novokuznetsk",
	305:  "Asia/Novosibirsk",
	304:  "Asia/Omsk",
	315:  "Asia/Oral",
	248:  "Asia/Phnom_Penh",
	313:  "Asia/Pontianak",
	274:  "Asia/Pyongyang",
	287:  "Asia/Qatar",
	314:  "Asia/Qyzylorda",
	247:  "Asia/Rangoon",
	288:  "Asia/Riyadh",
	301:  "Asia/Saigon",
	317:  "Asia/Sakhalin",
	299:  "Asia/Samarkand",
	273:  "Asia/Seoul",
	250:  "Asia/Shanghai",
	292:  "Asia/Singapore",
	341:  "Asia/Srednekolymsk",
	255:  "Asia/Taipei",
	300:  "Asia/Tashkent",
	258:  "Asia/Tbilisi",
	264:  "Asia/Tehran",
	778:  "Asia/Tel_Aviv",
	757:  "Asia/Thimbu",
	245:  "Asia/Thimphu",
	267:  "Asia/Tokyo",
	360:  "Asia/Tomsk",
	262:  "Asia/Ujung_Pandang",
	281:  "Asia/Ulaanbaatar",
	793:  "Asia/Ulan_Bator",
	252:  "Asia/Urumqi",
	327:  "Asia/Ust-Nera",
	276:  "Asia/Vientiane",
	309:  "Asia/Vladivostok",
	308:  "Asia/Yakutsk",
	361:  "Asia/Yangon",
	303:  "Asia/Yekaterinburg",
	241:  "Asia/Yerevan",
	336:  "Atlantic/Azores",
	330:  "Atlantic/Bermuda",
	338:  "Atlantic/Canary",
	339:  "Atlantic/Cape_Verde",
	845:  "Atlantic/Faeroe",
	333:  "Atlantic/Faroe",
	1421: "Atlantic/Jan_Mayen",
	337:  "Atlantic/Madeira",
	334:  "Atlantic/Reykjavik",
	332:  "Atlantic/South_Georgia",
	340:  "Atlantic/St_Helena",
	331:  "Atlantic/Stanley",
	864:  "Australia/ACT",
	349:  "Australia/Adelaide",
	347:  "Australia/Brisbane",
	353:  "Australia/Broken_Hill",
	1376: "Australia/Canberra",
	355:  "Australia/Currie",
	345:  "Australia/Darwin",
	356:  "Australia/Eucla",
	350:  "Australia/Hobart",
	866:  "Australia/LHI",
	348:  "Australia/Lindeman",
	354:  "Australia/Lord_Howe",
	351:  "Australia/Melbourne",
	857:  "Australia/North",
	1888: "Australia/NSW",
	346:  "Australia/Perth",
	859:  "Australia/Queensland",
	861:  "Australia/South",
	352:  "Australia/Sydney",
	862:  "Australia/Tasmania",
	863:  "Australia/Victoria",
	858:  "Australia/West",
	865:  "Australia/Yancowinna",
	705:  "Brazil/Acre",
	695:  "Brazil/DeNoronha",
	700:  "Brazil/East",
	704:  "Brazil/West",
	632:  "Canada/Atlantic",
	638:  "Canada/Central",
	639:  "Canada/East-Saskatchewan",
	634:  "Canada/Eastern",
	641:  "Canada/Mountain",
	630:  "Canada/Newfoundland",
	642:  "Canada/Pacific",
	1151: "Canada/Saskatchewan",
	650:  "Canada/Yukon",
	366:  "CET",
	706:  "Chile/Continental",
	963:  "Chile/EasterIsland",
	1637: "CST",
	215:  "CST6CDT",
	665:  "Cuba",
	368:  "EET",
	556:  "Egypt",
	883:  "Eire",
	211:  "EST",
	214:  "EST5EDT",
	1:    "Etc/GMT",
	1025: "Etc/GMT+0",
	16:   "Etc/GMT+1",
	25:   "Etc/GMT+10",
	26:   "Etc/GMT+11",
	27:   "Etc/GMT+12",
	17:   "Etc/GMT+2",
	18:   "Etc/GMT+3",
	19:   "Etc/GMT+4",
	20:   "Etc/GMT+5",
	21:   "Etc/GMT+6",
	22:   "Etc/GMT+7",
	23:   "Etc/GMT+8",
	24:   "Etc/GMT+9",
	3073: "Etc/GMT0",
	2049: "Etc/GMT-0",
	15:   "Etc/GMT-1",
	6:    "Etc/GMT-10",
	5:    "Etc/GMT-11",
	4:    "Etc/GMT-12",
	3:    "Etc/GMT-13",
	2:    "Etc/GMT-14",
	14:   "Etc/GMT-2",
	13:   "Etc/GMT-3",
	12:   "Etc/GMT-4",
	11:   "Etc/GMT-5",
	10:   "Etc/GMT-6",
	9:    "Etc/GMT-7",
	8:    "Etc/GMT-8",
	7:    "Etc/GMT-9",
	4097: "Etc/Greenwich",
	29:   "Etc/UCT",
	540:  "Etc/Universal",
	28:   "Etc/UTC",
	1564: "Etc/Zulu",
	396:  "Europe/Amsterdam",
	373:  "Europe/Andorra",
	344:  "Europe/Astrakhan",
	385:  "Europe/Athens",
	370:  "Europe/Belfast",
	412:  "Europe/Belgrade",
	383:  "Europe/Berlin",
	890:  "Europe/Bratislava",
	376:  "Europe/Brussels",
	400:  "Europe/Bucharest",
	386:  "Europe/Budapest",
	328:  "Europe/Busingen",
	393:  "Europe/Chisinau",
	379:  "Europe/Copenhagen",
	371:  "Europe/Dublin",
	384:  "Europe/Gibraltar",
	2417: "Europe/Guernsey",
	381:  "Europe/Helsinki",
	2929: "Europe/Isle_of_Man",
	407:  "Europe/Istanbul",
	1905: "Europe/Jersey",
	401:  "Europe/Kaliningrad",
	408:  "Europe/Kiev",
	357:  "Europe/Kirov",
	399:  "Europe/Lisbon",
	924:  "Europe/Ljubljana",
	369:  "Europe/London",
	391:  "Europe/Luxembourg",
	404:  "Europe/Madrid",
	392:  "Europe/Malta",
	893:  "Europe/Mariehamn",
	375:  "Europe/Minsk",
	395:  "Europe/Monaco",
	402:  "Europe/Moscow",
	769:  "Europe/Nicosia",
	397:  "Europe/Oslo",
	382:  "Europe/Paris",
	2972: "Europe/Podgorica",
	378:  "Europe/Prague",
	388:  "Europe/Riga",
	387:  "Europe/Rome",
	403:  "Europe/Samara",
	1411: "Europe/San_Marino",
	1436: "Europe/Sarajevo",
	364:  "Europe/Saratov",
	411:  "Europe/Simferopol",
	1948: "Europe/Skopje",
	377:  "Europe/Sofia",
	405:  "Europe/Stockholm",
	380:  "Europe/Tallinn",
	372:  "Europe/Tirane",
	905:  "Europe/Tiraspol",
	358:  "Europe/Ulyanovsk",
	409:  "Europe/Uzhgorod",
	389:  "Europe/Vaduz",
	899:  "Europe/Vatican",
	374:  "Europe/Vienna",
	390:  "Europe/Vilnius",
	413:  "Europe/Volgograd",
	398:  "Europe/Warsaw",
	2460: "Europe/Zagreb",
	410:  "Europe/Zaporozhye",
	406:  "Europe/Zurich",
	881:  "GB",
	1393: "GB-Eire",
	513:  "GMT",
	1537: "GMT+0",
	3585: "GMT0",
	2561: "GMT-0",
	4609: "Greenwich",
	766:  "Hongkong",
	213:  "HST",
	846:  "Iceland",
	438:  "Indian/Antananarivo",
	436:  "Indian/Chagos",
	439:  "Indian/Christmas",
	440:  "Indian/Cocos",
	441:  "Indian/Comoro",
	435:  "Indian/Kerguelen",
	442:  "Indian/Mahe",
	437:  "Indian/Maldives",
	443:  "Indian/Mauritius",
	444:  "Indian/Mayotte",
	445:  "Indian/Reunion",
	776:  "Iran",
	1290: "Israel",
	674:  "Jamaica",
	779:  "Japan",
	976:  "Kwajalein",
	568:  "Libya",
	367:  "MET",
	1169: "Mexico/BajaNorte",
	656:  "Mexico/BajaSur",
	653:  "Mexico/General",
	212:  "MST",
	216:  "MST7MDT",
	614:  "Navajo",
	983:  "NZ",
	984:  "NZ-CHAT",
	479:  "Pacific/Apia",
	471:  "Pacific/Auckland",
	342:  "Pacific/Bougainville",
	472:  "Pacific/Chatham",
	238:  "Pacific/Chuuk",
	451:  "Pacific/Easter",
	488:  "Pacific/Efate",
	460:  "Pacific/Enderbury",
	482:  "Pacific/Fakaofo",
	454:  "Pacific/Fiji",
	484:  "Pacific/Funafuti",
	452:  "Pacific/Galapagos",
	455:  "Pacific/Gambier",
	481:  "Pacific/Guadalcanal",
	458:  "Pacific/Guam",
	450:  "Pacific/Honolulu",
	485:  "Pacific/Johnston",
	461:  "Pacific/Kiritimati",
	468:  "Pacific/Kosrae",
	464:  "Pacific/Kwajalein",
	463:  "Pacific/Majuro",
	456:  "Pacific/Marquesas",
	486:  "Pacific/Midway",
	469:  "Pacific/Nauru",
	473:  "Pacific/Niue",
	474:  "Pacific/Norfolk",
	470:  "Pacific/Noumea",
	478:  "Pacific/Pago_Pago",
	475:  "Pacific/Palau",
	477:  "Pacific/Pitcairn",
	239:  "Pacific/Pohnpei",
	467:  "Pacific/Ponape",
	476:  "Pacific/Port_Moresby",
	453:  "Pacific/Rarotonga",
	462:  "Pacific/Saipan",
	1502: "Pacific/Samoa",
	457:  "Pacific/Tahiti",
	459:  "Pacific/Tarawa",
	483:  "Pacific/Tongatapu",
	466:  "Pacific/Truk",
	487:  "Pacific/Wake",
	489:  "Pacific/Wallis",
	978:  "Pacific/Yap",
	910:  "Poland",
	911:  "Portugal",
	762:  "PRC",
	2151: "PST",
	217:  "PST8PDT",
	767:  "ROC",
	785:  "ROK",
	804:  "Singapore",
	919:  "Turkey",
	541:  "UCT",
	1052: "Universal",
	618:  "US/Alaska",
	1132: "US/Aleutian",
	621:  "US/Arizona",
	613:  "US/Central",
	1135: "US/East-Indiana",
	612:  "US/Eastern",
	962:  "US/Hawaii",
	1137: "US/Indiana-Starke",
	628:  "US/Michigan",
	1126: "US/Mountain",
	615:  "US/Pacific",
	1639: "US/Pacific-New",
	990:  "US/Samoa",
	5121: "UTC",
	914:  "W-SU",
	365:  "WET",
	2076: "Zulu",
	//46:   "Africa/Asmera",
	//58:   "Africa/Bamako",
	//37:   "Africa/Bangui",
	//49:   "Africa/Banjul",
	//52:   "Africa/Bissau",
	//57:   "Africa/Blantyre",
	//35:   "Africa/Bujumbura",
	//44:   "Africa/Cairo",
	//61:   "Africa/Casablanca",
	//51:   "Africa/Conakry",
	//69:   "Africa/Dakar",
	//75:   "Africa/Dar_es_Salaam",
	//43:   "Africa/Djibouti",
	//36:   "Africa/Douala",
	//70:   "Africa/Freetown",
	//33:   "Africa/Gaborone",
	//80:   "Africa/Harare",
	//72:   "Africa/Johannesburg",
	//78:   "Africa/Kampala",
	//73:   "Africa/Khartoum",
	//67:   "Africa/Kigali",
	//39:   "Africa/Kinshasa",
	//66:   "Africa/Lagos",
	//48:   "Africa/Libreville",
	//76:   "Africa/Lome",
	//31:   "Africa/Luanda",
	//40:   "Africa/Lubumbashi",
	//79:   "Africa/Lusaka",
	//45:   "Africa/Malabo",
	//63:   "Africa/Maputo",
	//54:   "Africa/Maseru",
	//74:   "Africa/Mbabane",
	//71:   "Africa/Mogadishu",
	//55:   "Africa/Monrovia",
	//53:   "Africa/Nairobi",
	//38:   "Africa/Ndjamena",
	//65:   "Africa/Niamey",
	//60:   "Africa/Nouakchott",
	//34:   "Africa/Ouagadougou",
	//32:   "Africa/Porto-Novo",
	//68:   "Africa/Sao_Tome",
	//59:   "Africa/Timbuktu",
	//56:   "Africa/Tripoli",
	//77:   "Africa/Tunis",
	//64:   "Africa/Windhoek",
	//108:  "America/Adak",
	//106:  "America/Anchorage",
	//146:  "America/Anguilla",
	//147:  "America/Antigua",
	//181:  "America/Aruba",
	//200:  "America/Asuncion",
	//149:  "America/Barbados",
	//150:  "America/Belize",
	//195:  "America/Bogota",
	//175:  "America/Buenos_Aires",
	//205:  "America/Caracas",
	//198:  "America/Cayenne",
	//151:  "America/Cayman",
	//101:  "America/Chicago",
	//152:  "America/Costa_Rica",
	//189:  "America/Cuiaba",
	//196:  "America/Curacao",
	//131:  "America/Dawson_Creek",
	//102:  "America/Denver",
	//154:  "America/Dominica",
	//129:  "America/Edmonton",
	//156:  "America/El_Salvador",
	//185:  "America/Fortaleza",
	//207:  "America/Godthab",
	//172:  "America/Grand_Turk",
	//157:  "America/Grenada",
	//158:  "America/Guadeloupe",
	//159:  "America/Guatemala",
	//197:  "America/Guayaquil",
	//199:  "America/Guyana",
	//120:  "America/Halifax",
	//153:  "America/Havana",
	//111:  "America/Indianapolis",
	//162:  "America/Jamaica",
	//182:  "America/La_Paz",
	//201:  "America/Lima",
	//103:  "America/Los_Angeles",
	//165:  "America/Managua",
	//192:  "America/Manaus",
	//163:  "America/Martinique",
	//144:  "America/Mazatlan",
	//141:  "America/Mexico_City",
	//170:  "America/Miquelon",
	//204:  "America/Montevideo",
	//122:  "America/Montreal",
	//164:  "America/Montserrat",
	//148:  "America/Nassau",
	//100:  "America/New_York",
	//183:  "America/Noronha",
	//166:  "America/Panama",
	//202:  "America/Paramaribo",
	//109:  "America/Phoenix",
	//160:  "America/Port-au-Prince",
	//203:  "America/Port_of_Spain",
	//193:  "America/Porto_Acre",
	//167:  "America/Puerto_Rico",
	//127:  "America/Regina",
	//194:  "America/Santiago",
	//155:  "America/Santo_Domingo",
	//188:  "America/Sao_Paulo",
	//206:  "America/Scoresbysund",
	//118:  "America/St_Johns",
	//168:  "America/St_Kitts",
	//169:  "America/St_Lucia",
	//174:  "America/St_Thomas",
	//171:  "America/St_Vincent",
	//161:  "America/Tegucigalpa",
	//208:  "America/Thule",
	//145:  "America/Tijuana",
	//173:  "America/Tortola",
	//130:  "America/Vancouver",
	//126:  "America/Winnipeg",
	//2151: "PST",
	//1636: "EST",
	//1637: "CST",
	//230:  "Antarctica/Casey",
	//233:  "Antarctica/DumontDUrville",
	//232:  "Antarctica/Mawson",
	//236:  "Antarctica/McMurdo",
	//235:  "Antarctica/Palmer",
	//302:  "Asia/Aden",
	//268:  "Asia/Amman",
	//312:  "Asia/Anadyr",
	//271:  "Asia/Aqtau",
	//270:  "Asia/Aqtobe",
	//297:  "Asia/Ashkhabad",
	//265:  "Asia/Baghdad",
	//243:  "Asia/Bahrain",
	//242:  "Asia/Baku",
	//296:  "Asia/Bangkok",
	//277:  "Asia/Beirut",
	//272:  "Asia/Bishkek",
	//246:  "Asia/Brunei",
	//260:  "Asia/Calcutta",
	//293:  "Asia/Colombo",
	//244:  "Asia/Dacca",
	//294:  "Asia/Damascus",
	//298:  "Asia/Dubai",
	//295:  "Asia/Dushanbe",
	//254:  "Asia/Hong_Kong",
	//307:  "Asia/Irkutsk",
	//261:  "Asia/Jakarta",
	//263:  "Asia/Jayapura",
	//266:  "Asia/Jerusalem",
	//240:  "Asia/Kabul",
	//311:  "Asia/Kamchatka",
	//284:  "Asia/Karachi",
	//282:  "Asia/Katmandu",
	//306:  "Asia/Krasnoyarsk",
	//278:  "Asia/Kuala_Lumpur",
	//275:  "Asia/Kuwait",
	//256:  "Asia/Macao",
	//310:  "Asia/Magadan",
	//286:  "Asia/Manila",
	//283:  "Asia/Muscat",
	//257:  "Asia/Nicosia",
	//305:  "Asia/Novosibirsk",
	//248:  "Asia/Phnom_Penh",
	//274:  "Asia/Pyongyang",
	//287:  "Asia/Qatar",
	//247:  "Asia/Rangoon",
	//288:  "Asia/Riyadh",
	//301:  "Asia/Saigon",
	//273:  "Asia/Seoul",
	//250:  "Asia/Shanghai",
	//292:  "Asia/Singapore",
	//255:  "Asia/Taipei",
	//300:  "Asia/Tashkent",
	//258:  "Asia/Tbilisi",
	//264:  "Asia/Tehran",
	//245:  "Asia/Thimbu",
	//267:  "Asia/Tokyo",
	//262:  "Asia/Ujung_Pandang",
	//772:  "Asia/Kolkata",
	//793:  "Asia/Ulan_Bator",
	//276:  "Asia/Vientiane",
	//309:  "Asia/Vladivostok",
	//308:  "Asia/Yakutsk",
	//303:  "Asia/Yekaterinburg",
	//241:  "Asia/Yerevan",
	//336:  "Atlantic/Azores",
	//330:  "Atlantic/Bermuda",
	//338:  "Atlantic/Canary",
	//339:  "Atlantic/Cape_Verde",
	//333:  "Atlantic/Faeroe",
	//335:  "Atlantic/Jan_Mayen",
	//334:  "Atlantic/Reykjavik",
	//332:  "Atlantic/South_Georgia",
	//340:  "Atlantic/St_Helena",
	//331:  "Atlantic/Stanley",
	//349:  "Australia/Adelaide",
	//347:  "Australia/Brisbane",
	//345:  "Australia/Darwin",
	//346:  "Australia/Perth",
	//352:  "Australia/Sydney",
	//864:  "Australia/ACT",
	//368:  "EET",
	//513:  "GMT",
	//540:  "UTC",
	//367:  "MET",
	//2662: "MST",
	//1474: "HST",
	//396:  "Europe/Amsterdam",
	//373:  "Europe/Andorra",
	//385:  "Europe/Athens",
	//412:  "Europe/Belgrade",
	//383:  "Europe/Berlin",
	//376:  "Europe/Brussels",
	//400:  "Europe/Bucharest",
	//386:  "Europe/Budapest",
	//393:  "Europe/Chisinau",
	//379:  "Europe/Copenhagen",
	//371:  "Europe/Dublin",
	//384:  "Europe/Gibraltar",
	//381:  "Europe/Helsinki",
	//407:  "Europe/Istanbul",
	//401:  "Europe/Kaliningrad",
	//408:  "Europe/Kiev",
	//399:  "Europe/Lisbon",
	//369:  "Europe/London",
	//391:  "Europe/Luxembourg",
	//404:  "Europe/Madrid",
	//392:  "Europe/Malta",
	//375:  "Europe/Minsk",
	//395:  "Europe/Monaco",
	//402:  "Europe/Moscow",
	//397:  "Europe/Oslo",
	//382:  "Europe/Paris",
	//378:  "Europe/Prague",
	//388:  "Europe/Riga",
	//387:  "Europe/Rome",
	//403:  "Europe/Samara",
	//411:  "Europe/Simferopol",
	//377:  "Europe/Sofia",
	//405:  "Europe/Stockholm",
	//380:  "Europe/Tallinn",
	//372:  "Europe/Tirane",
	//389:  "Europe/Vaduz",
	//374:  "Europe/Vienna",
	//390:  "Europe/Vilnius",
	//398:  "Europe/Warsaw",
	//406:  "Europe/Zurich",
	//438:  "Indian/Antananarivo",
	//436:  "Indian/Chagos",
	//439:  "Indian/Christmas",
	//440:  "Indian/Cocos",
	//441:  "Indian/Comoro",
	//435:  "Indian/Kerguelen",
	//442:  "Indian/Mahe",
	//437:  "Indian/Maldives",
	//443:  "Indian/Mauritius",
	//444:  "Indian/Mayotte",
	//445:  "Indian/Reunion",
	//479:  "Pacific/Apia",
	//471:  "Pacific/Auckland",
	//472:  "Pacific/Chatham",
	//451:  "Pacific/Easter",
	//488:  "Pacific/Efate",
	//460:  "Pacific/Enderbury",
	//482:  "Pacific/Fakaofo",
	//454:  "Pacific/Fiji",
	//484:  "Pacific/Funafuti",
	//452:  "Pacific/Galapagos",
	//455:  "Pacific/Gambier",
	//481:  "Pacific/Guadalcanal",
	//458:  "Pacific/Guam",
	//450:  "Pacific/Honolulu",
	//461:  "Pacific/Kiritimati",
	//468:  "Pacific/Kosrae",
	//463:  "Pacific/Majuro",
	//456:  "Pacific/Marquesas",
	//469:  "Pacific/Nauru",
	//473:  "Pacific/Niue",
	//474:  "Pacific/Norfolk",
	//470:  "Pacific/Noumea",
	//478:  "Pacific/Pago_Pago",
	//475:  "Pacific/Palau",
	//477:  "Pacific/Pitcairn",
	//467:  "Pacific/Ponape",
	//476:  "Pacific/Port_Moresby",
	//453:  "Pacific/Rarotonga",
	//462:  "Pacific/Saipan",
	//457:  "Pacific/Tahiti",
	//459:  "Pacific/Tarawa",
	//483:  "Pacific/Tongatapu",
	//466:  "Pacific/Truk",
	//487:  "Pacific/Wake",
	//489:  "Pacific/Wallis",
	//41:   "Africa/Brazzaville",
	//556:  "Egypt",
	//81:   "Africa/Ceuta",
	//62:   "Africa/El_Aaiun",
	//568:  "Libya",
	//620:  "America/Atka",
	//1132: "US/Aleutian",
	//618:  "US/Alaska",
	//186:  "America/Araguaina",
	//184:  "America/Belem",
	//191:  "America/Boa_Vista",
	//110:  "America/Boise",
	//135:  "America/Cambridge_Bay",
	//140:  "America/Cancun",
	//179:  "America/Catamarca",
	//1125: "CST6CDT",
	//613:  "US/Central",
	//142:  "America/Chihuahua",
	//177:  "America/Cordoba",
	//139:  "America/Dawson",
	//1638: "America/Shiprock",
	//2150: "MST7MDT",
	//614:  "Navajo",
	//1126: "US/Mountain",
	//116:  "America/Detroit",
	//628:  "US/Michigan",
	//641:  "Canada/Mountain",
	//121:  "America/Glace_Bay",
	//119:  "America/Goose_Bay",
	//632:  "Canada/Atlantic",
	//665:  "Cuba",
	//143:  "America/Hermosillo",
	//113:  "America/Indiana/Knox",
	//625:  "America/Knox_IN",
	//1137: "US/Indiana-Starke",
	//112:  "America/Indiana/Marengo",
	//114:  "America/Indiana/Vevay",
	//623:  "America/Fort_Wayne",
	//1647: "America/Indiana/Indianapolis",
	//1135: "US/East-Indiana",
	//137:  "America/Inuvik",
	//133:  "America/Iqaluit",
	//674:  "Jamaica",
	//178:  "America/Jujuy",
	//104:  "America/Juneau",
	//1127: "PST8PDT",
	//615:  "US/Pacific",
	//1639: "US/Pacific-New",
	//115:  "America/Louisville",
	//187:  "America/Maceio",
	//704:  "Brazil/West",
	//656:  "Mexico/BajaSur",
	//180:  "America/Mendoza",
	//117:  "America/Menominee",
	//653:  "Mexico/General",
	//634:  "Canada/Eastern",
	//1124: "EST5EDT",
	//612:  "US/Eastern",
	//124:  "America/Nipigon",
	//107:  "America/Nome",
	//695:  "Brazil/DeNoronha",
	//132:  "America/Pangnirtung",
	//621:  "US/Arizona",
	//705:  "Brazil/Acre",
	//190:  "America/Porto_Velho",
	//125:  "America/Rainy_River",
	//134:  "America/Rankin_Inlet",
	//639:  "Canada/East-Saskatchewan",
	//1151: "Canada/Saskatchewan",
	//176:  "America/Rosario",
	//706:  "Chile/Continental",
	//700:  "Brazil/East",
	//630:  "Canada/Newfoundland",
	//686:  "America/Virgin",
	//128:  "America/Swift_Current",
	//123:  "America/Thunder_Bay",
	//657:  "America/Ensenada",
	//1169: "Mexico/BajaNorte",
	//642:  "Canada/Pacific",
	//138:  "America/Whitehorse",
	//650:  "Canada/Yukon",
	//638:  "Canada/Central",
	//105:  "America/Yakutat",
	//136:  "America/Yellowknife",
	//231:  "Antarctica/Davis",
	//748:  "Antarctica/South_Pole",
	//234:  "Antarctica/Syowa",
	//269:  "Asia/Almaty",
	//251:  "Asia/Chungking",
	//259:  "Asia/Dili",
	//285:  "Asia/Gaza",
	//249:  "Asia/Harbin",
	//766:  "Hongkong",
	//280:  "Asia/Hovd",
	//1431: "Asia/Istanbul",
	//778:  "Asia/Tel_Aviv",
	//1290: "Israel",
	//253:  "Asia/Kashgar",
	//279:  "Asia/Kuching",
	//304:  "Asia/Omsk",
	//289:  "Asia/Riyadh87",
	//801:  "Mideast/Riyadh87",
	//290:  "Asia/Riyadh88",
	//802:  "Mideast/Riyadh88",
	//291:  "Asia/Riyadh89",
	//803:  "Mideast/Riyadh89",
	//299:  "Asia/Samarkand",
	//785:  "ROK",
	//762:  "PRC",
	//804:  "Singapore",
	//767:  "ROC",
	//776:  "Iran",
	//779:  "Japan",
	//281:  "Asia/Ulaanbaatar",
	//252:  "Asia/Urumqi",
	//337:  "Atlantic/Madeira",
	//846:  "Iceland",
	//861:  "Australia/South",
	//859:  "Australia/Queensland",
	//353:  "Australia/Broken_Hill",
	//865:  "Australia/Yancowinna",
	//857:  "Australia/North",
	//350:  "Australia/Hobart",
	//862:  "Australia/Tasmania",
	//348:  "Australia/Lindeman",
	//354:  "Australia/Lord_Howe",
	//866:  "Australia/LHI",
	//351:  "Australia/Melbourne",
	//863:  "Australia/Victoria",
	//858:  "Australia/West",
	//1376: "Australia/Canberra",
	//1888: "Australia/NSW",
	//366:  "CET",
	//1:    "Etc/GMT",
	//1025: "Etc/GMT+0",
	//2049: "Etc/GMT-0",
	//3073: "Etc/GMT0",
	//4097: "Etc/Greenwich",
	//1537: "GMT+0",
	//2561: "GMT-0",
	//3585: "GMT0",
	//4609: "Greenwich",
	//16:   "Etc/GMT+1",
	//25:   "Etc/GMT+10",
	//26:   "Etc/GMT+11",
	//27:   "Etc/GMT+12",
	//17:   "Etc/GMT+2",
	//18:   "Etc/GMT+3",
	//19:   "Etc/GMT+4",
	//20:   "Etc/GMT+5",
	//21:   "Etc/GMT+6",
	//22:   "Etc/GMT+7",
	//23:   "Etc/GMT+8",
	//24:   "Etc/GMT+9",
	//15:   "Etc/GMT-1",
	//6:    "Etc/GMT-10",
	//5:    "Etc/GMT-11",
	//4:    "Etc/GMT-12",
	//3:    "Etc/GMT-13",
	//2:    "Etc/GMT-14",
	//14:   "Etc/GMT-2",
	//13:   "Etc/GMT-3",
	//12:   "Etc/GMT-4",
	//11:   "Etc/GMT-5",
	//10:   "Etc/GMT-6",
	//9:    "Etc/GMT-7",
	//8:    "Etc/GMT-8",
	//7:    "Etc/GMT-9",
	//29:   "Etc/UCT",
	//541:  "UCT",
	//28:   "Etc/UTC",
	//1052: "Etc/Universal",
	//2076: "Etc/Zulu",
	//1564: "Universal",
	//2588: "Zulu",
	//370:  "Europe/Belfast",
	//924:  "Europe/Ljubljana",
	//1436: "Europe/Sarajevo",
	//1948: "Europe/Skopje",
	//2460: "Europe/Zagreb",
	//883:  "Eire",
	//919:  "Turkey",
	//911:  "Portugal",
	//881:  "GB",
	//1393: "GB-Eire",
	//914:  "W-SU",
	//890:  "Europe/Bratislava",
	//1411: "Europe/San_Marino",
	//899:  "Europe/Vatican",
	//394:  "Europe/Tiraspol",
	//409:  "Europe/Uzhgorod",
	//910:  "Poland",
	//410:  "Europe/Zaporozhye",
	//983:  "NZ",
	//984:  "NZ-CHAT",
	//963:  "Chile/EasterIsland",
	//962:  "US/Hawaii",
	//485:  "Pacific/Johnston",
	//464:  "Pacific/Kwajalein",
	//976:  "Kwajalein",
	//486:  "Pacific/Midway",
	//1502: "Pacific/Samoa",
	//990:  "US/Samoa",
	//465:  "Pacific/Yap",
	//365:  "WET",
}

// EncodeDate convert time.Time into oracle representation
func EncodeDate(ti time.Time) []byte {
	ret := make([]byte, 7)
	ret[0] = uint8(ti.Year()/100 + 100)
	ret[1] = uint8(ti.Year()%100 + 100)
	ret[2] = uint8(ti.Month())
	ret[3] = uint8(ti.Day())
	ret[4] = uint8(ti.Hour() + 1)
	ret[5] = uint8(ti.Minute() + 1)
	ret[6] = uint8(ti.Second() + 1)
	return ret
}

func EncodeTimeStamp(ti time.Time, withTZ bool) []byte {
	ret := make([]byte, 11)
	ret[0] = uint8(ti.Year()/100 + 100)
	ret[1] = uint8(ti.Year()%100 + 100)
	ret[2] = uint8(ti.Month())
	ret[3] = uint8(ti.Day())
	ret[4] = uint8(ti.Hour() + 1)
	ret[5] = uint8(ti.Minute() + 1)
	ret[6] = uint8(ti.Second() + 1)
	binary.BigEndian.PutUint32(ret[7:11], uint32(ti.Nanosecond()))
	if withTZ {
		zoneLoc := ti.Location()
		zoneID := 0
		for key, val := range oracleZones {
			if strings.EqualFold(zoneLoc.String(), val) {
				zoneID = key
				break
			}
		}
		// if (((int) numArray[11] & 128) != 0)
		// {
		// numArray[12] |= (byte) 1;
		// if (dst)
		// numArray[12] |= (byte) 2;
		// }
		// else
		// numArray[11] |= (byte) 64;
		if zoneID > 0 {
			zone1 := uint8((zoneID&0x1FC0)>>6) | 0x80
			zone2 := uint8((zoneID & 0x3F) << 2)
			ret = append(ret, zone1, zone2)

		} else {
			_, offset := ti.Zone()
			zone1 := uint8(offset/3600) + 20
			zone2 := uint8((offset/60)%60) + 60
			ret = append(ret, zone1, zone2)
		}

	}
	return ret
}

// DecodeDate convert oracle time representation into time.Time
func DecodeDate(data []byte) (time.Time, error) {
	if len(data) < 7 {
		return time.Now(), errors.New("abnormal data representation for date")
	}
	year := (int(data[0]) - 100) * 100
	year += int(data[1]) - 100
	nanoSec := 0
	tzHour := 0
	tzMin := 0
	if len(data) > 10 {
		nanoSec = int(binary.BigEndian.Uint32(data[7:11]))
	}
	if len(data) > 11 {
		tzHour = int(data[11]&0x3F) - 20
	}
	if len(data) > 12 {
		tzMin = int(data[12]) - 60
	}
	if tzHour == 0 && tzMin == 0 {
		return time.Date(year, time.Month(data[2]), int(data[3]),
			int(data[4]-1), int(data[5]-1), int(data[6]-1), nanoSec, time.UTC), nil
	}
	var zone *time.Location
	var timeInZone bool
	//var err error
	//fmt.Println(data)
	if data[11]&0x80 != 0 {
		var regionCode = (int(data[11]) & 0x7F) << 6
		regionCode += (int(data[12]) & 0xFC) >> 2
		timeInZone = data[12]&0x1 == 1
		name, found := oracleZones[regionCode]
		if found {
			zone, _ = time.LoadLocation(name)
			//if err == nil {
			//	return time.Now(), errors.New("Error decode timezone:" + err.Error())
			//}
		}

		//loc, err := time.Parse("-0700", fmt.Sprintf("%+03d%02d", tzHour, tzMin))
		//if err != nil {
		//	return time.Date(year, time.Month(data[2]), int(data[3]),
		//		int(data[4]-1)+tzHour, int(data[5]-1)+tzMin, int(data[6]-1), nanoSec, time.UTC), nil
		//} else {
		//	return time.Date(year, time.Month(data[2]), int(data[3]),
		//		int(data[4]-1)+tzHour, int(data[5]-1)+tzMin, int(data[6]-1), nanoSec, loc.Location()), nil
		//}
	}
	if zone == nil {
		zone = time.FixedZone(fmt.Sprintf("%+03d:%02d", tzHour, tzMin), tzHour*60*60+tzMin*60)
		timeInZone = true
	}
	if timeInZone {
		return time.Date(year, time.Month(data[2]), int(data[3]),
			int(data[4]-1), int(data[5]-1), int(data[6]-1), nanoSec, zone), nil
	}
	ret := time.Date(year, time.Month(data[2]), int(data[3]),
		int(data[4]-1), int(data[5]-1), int(data[6]-1), nanoSec, time.UTC)
	return ret.In(zone), nil
	//return time.Date(year, time.Month(data[2]), int(data[3]),
	//	int(data[4]-1)+tzHour, int(data[5]-1)+tzMin, int(data[6]-1), nanoSec, time.UTC), nil
}

// addDigitToMantissa return the mantissa with the added digit if the carry is not
// set by the add. Othervise, return the mantissa untouched and carry = true.
func addDigitToMantissa(mantissaIn uint64, d byte) (mantissaOut uint64, carryOut bool) {
	var carry uint64
	mantissaOut = mantissaIn

	if mantissaIn != 0 {
		var over uint64
		over, mantissaOut = bits.Mul64(mantissaIn, uint64(10))
		if over != 0 {
			return mantissaIn, true
		}
	}
	mantissaOut, carry = bits.Add64(mantissaOut, uint64(d), carry)
	if carry != 0 {
		return mantissaIn, true
	}
	return mantissaOut, false
}

// FromNumber decode Oracle binary representation of numbers
// and returns mantissa, negative and exponent
// Some documentation:
//
//		https://gotodba.com/2015/03/24/how-are-numbers-saved-in-oracle/
//	 https://www.orafaq.com/wiki/Number
func FromNumber(inputData []byte) (mantissa uint64, negative bool, exponent int, mantissaDigits int, err error) {
	if len(inputData) == 0 {
		return 0, false, 0, 0, fmt.Errorf("Invalid NUMBER")
	}
	if inputData[0] == 0x80 {
		return 0, false, 0, 0, nil
	}

	negative = inputData[0]&0x80 == 0
	if negative {
		exponent = int(inputData[0]^0x7f) - 64
	} else {
		exponent = int(inputData[0]&0x7f) - 64
	}

	buf := inputData[1:]
	// When negative, strip the last byte if equal 0x66
	if negative && inputData[len(inputData)-1] == 0x66 {
		buf = inputData[1 : len(inputData)-1]
	}

	carry := false // get true when mantissa exceeds 64 bits
	firstDigitWasZero := 0

	// Loop on mantissa digits, stop with the capacity of int64 is reached
	// Beyond, digits will be lost during convertion t
	mantissaDigits = 0
	for p, digit100 := range buf {
		if p == 0 {
			firstDigitWasZero = -1
		}
		digit100--
		if negative {
			digit100 = 100 - digit100
		}

		mantissa, carry = addDigitToMantissa(mantissa, digit100/10)
		if carry {
			break
		}
		mantissaDigits++

		mantissa, carry = addDigitToMantissa(mantissa, digit100%10)
		if carry {
			break
		}
		mantissaDigits++
	}

	exponent = exponent*2 - mantissaDigits // Adjust exponent to the retrieved mantissa
	return mantissa, negative, exponent, mantissaDigits + firstDigitWasZero, nil
}

// DecodeDouble decode NUMBER as a float64
// Please note limitations Oracle NUMBER can have 38 significant digits while
// Float64 have 51 bits. Convertion can't be perfect.
func DecodeDouble(inputData []byte) float64 {
	mantissa, negative, exponent, _, err := FromNumber(inputData)
	if err != nil {
		return math.NaN()
	}
	absExponent := int(math.Abs(float64(exponent)))
	if negative {
		return -math.Round(float64(mantissa)*math.Pow10(exponent)*math.Pow10(absExponent)) / math.Pow10(absExponent)
	}
	return math.Round(float64(mantissa)*math.Pow10(exponent)*math.Pow10(absExponent)) / math.Pow10(absExponent)

}

// DecodeInt convert NUMBER to int64
// Preserve all the possible bits of the mantissa when Int is between MinInt64 and MaxInt64 range
func DecodeInt(inputData []byte) int64 {
	mantissa, negative, exponent, _, err := FromNumber(inputData)
	if err != nil || exponent < 0 {
		return 0
	}

	for exponent > 0 {
		mantissa *= 10
		exponent--
	}
	if negative && (mantissa>>63) == 0 {
		return -int64(mantissa)
	}
	return int64(mantissa)
}

// DecodeNumber decode the given NUMBER and return an interface{} that could be either an int64 or a float64
//
// If the number can be represented by an integer it returns an int64
// Othervise, it returns a float64
//
// The sql.Parse will do the match with program need.
//
// Ex When parsing a float into an int64, the driver will try to cast the float64 into the int64.
// If the float64 can't be represented by an int64, Parse will issue an error "invalid syntax"
func DecodeNumber(inputData []byte) interface{} {
	var powerOfTen = [...]uint64{
		1, 10, 100, 1000, 10000, 100000, 1000000, 10000000, 100000000, 1000000000,
		10000000000, 100000000000, 1000000000000, 10000000000000, 100000000000000,
		1000000000000000, 10000000000000000, 100000000000000000, 1000000000000000000,
		10000000000000000000}

	mantissa, negative, exponent, mantissaDigits, err := FromNumber(inputData)
	if err != nil {
		return math.NaN()
	}

	if mantissaDigits == 0 {
		return int64(0)
	}

	if exponent >= 0 && exponent < len(powerOfTen) {
		// exponent = mantissaDigits - exponent
		IntMantissa := mantissa
		IntExponent := exponent
		var over uint64
		over, IntMantissa = bits.Mul64(IntMantissa, powerOfTen[IntExponent])
		if (!negative && IntMantissa > maxConvertibleInt) ||
			(negative && IntMantissa > maxConvertibleNegInt) {
			goto fallbackToFloat
		}
		if over != 0 {
			goto fallbackToFloat
		}

		if negative && (IntMantissa>>63) == 0 {
			return -int64(IntMantissa)
		}
		return int64(IntMantissa)
	}

fallbackToFloat:
	//if negative {
	//	return -float64(mantissa) * math.Pow10(exponent)
	//}
	//
	//return float64(mantissa) * math.Pow10(exponent)
	absExponent := int(math.Abs(float64(exponent)))
	if negative {
		return -math.Round(float64(mantissa)*math.Pow10(exponent)*math.Pow10(absExponent)) / math.Pow10(absExponent)
	}
	return math.Round(float64(mantissa)*math.Pow10(exponent)*math.Pow10(absExponent)) / math.Pow10(absExponent)
}

// ToNumber encode mantissa, sign and exponent as a []byte expected by Oracle
func ToNumber(mantissa []byte, negative bool, exponent int) []byte {

	if len(mantissa) == 0 {
		return []byte{128}
	}

	if exponent%2 == 0 {
		mantissa = append([]byte{'0'}, mantissa...)
	} else {
	}

	mantissaLen := len(mantissa)
	size := 1 + (mantissaLen+1)/2
	if negative && mantissaLen < 21 {
		size++
	}
	buf := make([]byte, size, size)

	for i := 0; i < mantissaLen; i += 2 {
		b := 10 * (mantissa[i] - '0')
		if i < mantissaLen-1 {
			b += mantissa[i+1] - '0'
		}
		if negative {
			b = 100 - b
		}
		buf[1+i/2] = b + 1
	}

	if negative && mantissaLen < 21 {
		buf[len(buf)-1] = 0x66
	}

	if exponent < 0 {
		exponent--
	}
	exponent = (exponent / 2) + 1
	if negative {
		buf[0] = byte(exponent+64) ^ 0x7f
	} else {
		buf[0] = byte(exponent+64) | 0x80
	}
	return buf
}

// EncodeUint64 encode an uint64 into an oracle NUMBER internal format
// Keep all significant bits of the uint64
func EncodeUint64(val uint64) []byte {
	mantissa := []byte(strconv.FormatUint(val, 10))
	exponent := len(mantissa) - 1
	trailingZeros := 0
	for i := len(mantissa) - 1; i >= 0 && mantissa[i] == '0'; i-- {
		trailingZeros++
	}
	mantissa = mantissa[:len(mantissa)-trailingZeros]
	return ToNumber(mantissa, false, exponent)
}

// EncodeInt64 encode an int64 into an oracle NUMBER internal format
// Keep all significant bits of the int64
func EncodeInt64(val int64) []byte {
	mantissa := []byte(strconv.FormatInt(val, 10))
	negative := mantissa[0] == '-'
	if negative {
		mantissa = mantissa[1:]
	}
	exponent := len(mantissa) - 1
	trailingZeros := 0
	for i := len(mantissa) - 1; i >= 0 && mantissa[i] == '0'; i-- {
		trailingZeros++
	}
	mantissa = mantissa[:len(mantissa)-trailingZeros]
	return ToNumber(mantissa, negative, exponent)
}

// EncodeInt encode a int into an oracle NUMBER internal format
func EncodeInt(val int) []byte {
	return EncodeInt64(int64(val))
}

// EncodeDouble convert a float64 into binary NUMBER representation
func EncodeDouble(num float64) ([]byte, error) {
	if num == 0.0 {
		return []byte{128}, nil
	}

	var (
		exponent int
		err      error
	)
	mantissa := []byte(strconv.FormatFloat(num, 'e', -1, 64))
	if i := bytes.Index(mantissa, []byte{'e'}); i >= 0 {
		exponent, err = strconv.Atoi(string(mantissa[i+1:]))
		if err != nil {
			return nil, err
		}
		mantissa = mantissa[:i]
	}
	negative := mantissa[0] == '-'
	if negative {
		mantissa = mantissa[1:]
	}
	if i := bytes.Index(mantissa, []byte{'.'}); i >= 0 {
		mantissa = append(mantissa[:i], mantissa[i+1:]...)
	}
	return ToNumber(mantissa, negative, exponent), nil
}
