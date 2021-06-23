package shiro

func Check(url string) (key string) {
	getCommandArgs()
	shiro_url = url
	//httpProxy="http://127.0.0.1:8080"
	key = keyCheck(url)
	return key
}
