package nla_test

//func TestNewNegotiateMessage(t *testing.T) {
//	ntlm := nla.NewNTLMv2("", "", "")
//	negoMsg := ntlm.GetNegotiateMessage()
//	buff := &bytes.Buffer{}
//	struc.Pack(buff, negoMsg)
//
//	result := hex.EncodeToString(buff.Bytes())
//	expected := "4e544c4d535350000100000035820860000000000000000000000000000000000000000000000000"
//
//	if result != expected {
//		t.Error(result, " not equals to", expected)
//	}
//}
//
//func TestNTLMv2_ComputeResponse(t *testing.T) {
//	ntlm := nla.NewNTLMv2("", "", "")
//
//	ResponseKeyNT, _ := hex.DecodeString("39e32c766260586a9036f1ceb04c3007")
//	ResponseKeyLM, _ := hex.DecodeString("39e32c766260586a9036f1ceb04c3007")
//	ServerChallenge, _ := hex.DecodeString("adcb9d1c8d4a5ed8")
//	ClienChallenge, _ := hex.DecodeString("1a78bed8e5d5efa7")
//	Timestamp, _ := hex.DecodeString("a02f44f01267d501")
//	ServerName, _ := hex.DecodeString("02001e00570049004e002d00460037005200410041004d004100500034004a00430001001e00570049004e002d00460037005200410041004d004100500034004a00430004001e00570049004e002d00460037005200410041004d004100500034004a00430003001e00570049004e002d00460037005200410041004d004100500034004a00430007000800a02f44f01267d50100000000")
//
//	NtChallengeResponse, LmChallengeResponse, SessionBaseKey := ntlm.ComputeResponse(ResponseKeyNT, ResponseKeyLM, ServerChallenge, ClienChallenge, Timestamp, ServerName)
//
//	ntChallRespExpected := "4e7316531937d2fc91e7230853844b890101000000000000a02f44f01267d5011a78bed8e5d5efa70000000002001e00570049004e002d00460037005200410041004d004100500034004a00430001001e00570049004e002d00460037005200410041004d004100500034004a00430004001e00570049004e002d00460037005200410041004d004100500034004a00430003001e00570049004e002d00460037005200410041004d004100500034004a00430007000800a02f44f01267d50100000000"
//	lmChallRespExpected := "d4dc6edc0c37dd70f69b5c4f05a615661a78bed8e5d5efa7"
//	sessBaseKeyExpected := "034009be89a0507b2bd6d28e966e1dab"
//
//	if hex.EncodeToString(NtChallengeResponse) != ntChallRespExpected {
//		t.Error("NtChallengeResponse incorrect")
//	}
//
//	if hex.EncodeToString(LmChallengeResponse) != lmChallRespExpected {
//		t.Error("LmChallengeResponse incorrect")
//	}
//
//	if hex.EncodeToString(SessionBaseKey) != sessBaseKeyExpected {
//		t.Error("SessionBaseKey incorrect")
//	}
//}
//
//func TestSIGNKEY(t *testing.T) {
//	exportedSessionKey, _ := hex.DecodeString("be32c3c56ea6683200a35329d67880c3")
//	result := hex.EncodeToString(nla.SIGNKEY(exportedSessionKey, true))
//	expected := "79b4f9a4113230f378a0af99f784adae"
//	if result != expected {
//		t.Error(result, "not equal to", expected)
//	}
//}
