# POC列表

```
pocs_go:

 +-------------------+------------------+-------------------------------------------------------------+
 | 系统               | 编号             | 描述                                                         |
 +-------------------+------------------+-------------------------------------------------------------+
 | Springboot        | CVE-2022-22965   | Spring Framework RCE via Data Binding on JDK 9+             |
 | Springboot        | CVE-2022-22947   | spring cloud gateway 3.1.1+ and 3.0.7+ remote code execution|
 | Apache Log4j      | CVE-2021-44228   | 2.0 <= Apache log4j2 <= 2.14.1, log4j remote code execution |
 | Apache Shiro      | CVE-2016-4437    | <= 1.2.4, shiro-550, rememberme deserialization rce         |
 | Apache Tomcat     | CVE-2017-12615   | 7.0.0 - 7.0.81, put method any files upload                 |
 | Apache Tomcat     | CVE-2020-1938    | 6, 7 < 7.0.100, 8 < 8.5.51, 9 < 9.0.31 arbitrary file read  |
 | Fsatjson          | VER-1262         | <= 1.2.62 fastjson autotype remote code execution           |
 | Jboss             | CVE_2017_12149   | Jboss AS 5.x/6.x rce                                        |
 | Jenkins           | CVE-2018-1000110 | user search                                                 |
 | Jenkins           | CVE-2018-1000861 | <= 2.153, LTS <= 2.138.3, remote code execution             |
 | Jenkins           | CVE-2018-1003000 | Groovy <= 2.61 Script Security <= 1.49 remote code execution|
 | Jenkins           | Unauthorized     | Unauthorized Groovy script remote code execution            |
 | Oracle Weblogic   | CVE-2014-4210    | 10.0.2 - 10.3.6, weblogic ssrf vulnerability                |
 | Oracle Weblogic   | CVE-2017-3506    | 10.3.6.0, 12.1.3.0, 12.2.1.0-2, weblogic wls-wsat rce       |
 | Oracle Weblogic   | CVE-2017-10271   | 10.3.6.0, 12.1.3.0, 12.2.1.1-2, weblogic wls-wsat rce       |
 | Oracle Weblogic   | CVE-2018-2894    | 12.1.3.0, 12.2.1.2-3, deserialization any file upload       |
 | Oracle Weblogic   | CVE-2019-2725    | 10.3.6.0, 12.1.3.0, weblogic wls9-async deserialization rce |
 | Oracle Weblogic   | CVE-2019-2729    | 10.3.6.0, 12.1.3.0, weblogic wls9-async deserialization rce |
 | Oracle Weblogic   | CVE-2020-2883    | 10.3.6.0, 12.1.3.0, 12.2.1.3-4, iiop t3 deserialization rce |
 | Oracle Weblogic   | CVE-2020-14882   | 10.3.6.0, 12.1.3.0, 12.2.1.3-4, 14.1.1.0, console rce       |
 | Oracle Weblogic   | CVE-2020-14883   | 10.3.6.0, 12.1.3.0, 12.2.1.3-4, 14.1.1.0, console rce       |
 | Oracle Weblogic   | CVE-2021-2109    | 10.3.6.0, 12.1.3.0, 12.2.1.3-4, 14.1.1.0, unauthorized jndi |
 | PHPUnit           | CVE_2017_9841    | 4.x < 4.8.28, 5.x < 5.6.3, remote code execution            |
 | Seeyon            | *                | some poc                                                    |
 | ThinkPHP          | CVE-2019-9082    | < 3.2.4, thinkphp remote code execution                     |
 | ThinkPHP          | CVE-2018-20062   | <= 5.0.23, 5.1.31, thinkphp remote code execution           |
 +-------------------+------------------+-------------------------------------------------------------+
pocs_yml:

xrayV2 all pocs

```