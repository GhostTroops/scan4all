# 自定义扫描器

## go文件添加POC：

1.在 ./pkg/fingerprint/localFingerData.go 内检查或添加指纹

2.写一个go文件POC，放到pocs_go文件夹下，指定一个入口函数，指定输入输出，并在./pocs_go/go_poc_check.go 添加检测项（poc的编写过程可以使用./pkg/util.go内的函数pkg.HttpRequset）

例如：

CVE_2017_12615 POC：
```
func CVE_2017_12615(szUrl string) bool {
	if req, err := pkg.HttpRequset(szUrl+"/vtset.txt", "PUT", "test", false, nil); err == nil {
		if req.StatusCode == 204 || req.StatusCode == 201 {
			pkg.POClog(fmt.Sprintf("Found vuln Tomcat CVE_2017_12615|--\"%s/vtest.txt\"\n", szUrl))
			return true
		}
	}
	return false
}
```

CVE_2017_12615 POC ./pocs_go/go_poc_check.go 添加检测项：
```
case "Apache Tomcat":
   if tomcat.CVE_2017_12615(URL) {
		technologies = append(technologies, "exp-Tomcat|CVE_2017_12615")
    }
```
## yml文件添加POC：
1.在 ./pkg/fingerprint/localFingerData.go 内检查或添加指纹

2.参考 xrayV2 yml 的编写方式编写放至 ./pocs_yml/ymlFiles/ 下，文件名需以指纹名开头加- (如thinkphp-cvexxxxxxxxx-aaa.yml)

## 后台弱口令扫描，中间件弱口令扫描 字典

后台弱口令检测内置了两个账号 admin/test，密码为top100，如果成功识别首页有登录会标记为 LoginPage，如果识别可能是后台登录页会标记为 AdminLoginPage ，都会尝试构建登录包会自动检测弱口令

如：

`http://127.0.0.1:8080 [302,200] [登录 - 后台] [exp-shiro|key:Z3VucwAAAAAAAAAAAAAAAA==,Java,LoginPage,brute-admin|admin:123456] [http://127.0.0.1:8080/login]`

包含弱口令检测板块
1. 没有使用验证码，没有使用vue等前端框架的后台智能弱口令检测
2. basic弱口令检测
3. tomcat弱口令检测
4. weblogic弱口令检测
5. jboss弱口令检测

字典在 ./brute/dicts/ 内置，可自行修改


##  敏感文件扫描 字典

扫描 备份、swagger-ui、spring actuator、上传接口、测试文件等敏感文件

字典在 ./brute/dicts/ 内置，可自行修改