#!/usr/bin/env python3
import glob
import subprocess

def countTpl(path):
	return len(glob.glob(path + "/*.*"))

def command(args, start=None, end=None):
	return "\n".join(subprocess.run(args, text=True, capture_output=True).stdout.split("\n")[start:end])[:-1]

def get_top10():
	HEADER = "## Nuclei Templates Top 10 statistics\n\n"
	TOP10 = command(["cat", "config/nuclei-templates/TOP-10.md"])
	return HEADER + TOP10 if len(TOP10) > 0 else ""

if __name__ == "__main__":
	version = command(["git", "describe", "--tags", "--abbrev=0"])
	HEADER = '''[![Tweet](https://img.shields.io/twitter/url/http/Hktalent3135773.svg?style=social)](https://twitter.com/intent/follow?screen_name=Hktalent3135773) [![Follow on Twitter](https://img.shields.io/twitter/follow/Hktalent3135773.svg?style=social&label=Follow)](https://twitter.com/intent/follow?screen_name=Hktalent3135773) [![GitHub Followers](https://img.shields.io/github/followers/hktalent.svg?style=social&label=Follow)](https://github.com/hktalent/)'''
	END = '''# 交流群(微信、QQ、Tg)
             | Wechat | Or | QQchat | Or | Tg |
             | --- |--- |--- |--- |--- |
             |<img width=166 src=https://github.com/hktalent/scan4all/blob/main/static/wcq.JPG>||<img width=166 src=https://github.com/hktalent/scan4all/blob/main/static/qqc.jpg>||<img width=166 src=https://github.com/hktalent/scan4all/blob/main/static/tg.jpg>|


             ## 💖Star
             [![Stargazers over time](https://starchart.cc/hktalent/scan4all.svg)](https://starchart.cc/hktalent/scan4all)

             # Donation
             | Wechat Pay | AliPay | Paypal | BTC Pay |BCH Pay |
             | --- | --- | --- | --- | --- |
             |<img src=https://github.com/hktalent/myhktools/blob/master/md/wc.png>|<img width=166 src=https://github.com/hktalent/myhktools/blob/master/md/zfb.png>|[paypal](https://www.paypal.me/pwned2019) **miracletalent@gmail.com**|<img width=166 src=https://github.com/hktalent/myhktools/blob/master/md/BTC.png>|<img width=166 src=https://github.com/hktalent/myhktools/blob/master/md/BCH.jpg>|
'''
	template = HEADER + eval(open(".github/scripts/README.tmpl", "r").read()) + END

	print(template)
	f = open("README_CN.md", "w")
	f.write(template)
	f.close()
