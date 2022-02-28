package wappalyzer

var fingerprints = `
{
	"apps": {
		"LoginPage": {
			"html": [
				"<input.*pass"
			]
		},
		"Struts2": {
			"html": [
				"\\.action"
			]
		},
		"JSON": {
			"html": [
				"data.*?:.*?json.stringify",
				"json"
			]
		},
		"seeyon": {
			"html": [
				"<title>用友致远oa",
				"\/seeyon\/user-data\/images\/login\/login.gif",
				"\/seeyon\/common\/"
			]
		},
		"Spring env": {
			"html": [
				"logback",
				"servletcontextinitparams"
			]
		},
		"WebLogic": {
			"html": [
				"error 404--not found",
				"error 403--",
				"weblogic",
				"<i>hypertext transfer protocol -- http\/1.1<\/i>",
				"\/console\/framework\/skins\/wlsconsole\/images\/login_weblogic_branding.png"
			]
		},
		"Sangfor SSL VPN": {
			"html": [
				"loginpagesp\/loginprivacy.js",
				"\/por\/login_psw.csp"
			]
		},
		"Sangfor-EDR": {
			"html": [
				"<title>SANGFOR终端检测响应平台"
			]
		},
		"Ecology": {
			"meta": {
				"keywords": [
					"weaver",
					"e-mobile"
				]
			},
			"headers": {
				"set-cookie": "ecology_jsessionid",
				"cookie": "ecology_jsessionid"
			},
			"html": [
				"<title>移动管理平台-企业管理<\/title>",
				"=\"resizable=yes\""
			]
		},
		"Shiro": {
			"headers": {
				"set-cookie": "=deleteme",
				"cookie": "=deleteme"
			},
			"implies": [
				"Java"
			]
		},
		"ActiveMQ": {
			"html": [
				"<title>apache activemq<\/title>",
				"<h2>welcome to the apache activemq!<\/h2>"
			],
			"implies": [
				"Java"
			]
		},
		"Alibaba-Nacos": {
			"html": [
				"<title>nacos<\/title>"
			]
		},
		"Sunlogin": {
			"html": [
				"{\"success\":false,\"msg\":\"verification failure\"}"
			]
		},
		"Amtt-Hiboss": {
			"html": [
				"<title>酒店宽带运营系统<\/title>"
			]
		},
		"Apache-Flink": {
			"html": [
				"<title>apache flink web dashboard<\/title>",
				"<title>apache flink history server<\/title>"
			]
		},
		"ChinaUnicom-Modem": {
			"html": [
				"cu.html"
			]
		},
		"ECshop": {
			"headers": {
				"set-cookie": "ecs_id",
				"cookie": "ecs_id"
			}
		},
		"Elasticsearch": {
			"html": [
				"cluster_uuid"
			]
		},
		"Harbor": {
			"html": [
				"<title>harbor<\/title>"
			]
		},
		"Jellyfin": {
			"html": [
				"<title>jellyfin<\/title>"
			]
		},
		"Jumpserver": {
			"html": [
				"<script src=\"/static/js/jumpserver.js\"></script>",
				"<title>jumpserver<\/title>",
				"jumpserver.org organization"
			]
		},
		"Jupyter-Notebook": {
			"html": [
				"<title>jupyter notebook<\/title>"
			]
		},
		"kafka-manager": {
			"html": [
				"<title>kafka manager<\/title>"
			]
		},
		"netentsec": {
			"html": [
				"<title>网康下一代防火墙<\/title>"
			]
		},
		"Nexus": {
			"meta": {
				"description": [
					"nexus repository manager"
				]
			},
			"html": [
				"<title>nexus repository manager<\/title>"
			]
		},
		"phpstudy": {
			"html": [
				"<title>phpstudy"
			]
		},
		"shiziyu": {
			"html": [
				"<form action=\"\/seller.php"
			]
		},
		"shopxo": {
			"html": [
				"<meta name=\"apple-mobile-web-app-title\" content=\"shopxo\">"
			]
		},
		"showdoc": {
			"html": [
				"<title>showdoc<\/title>"
			]
		},
		"SkyWalking": {
			"html": [
				"<title>skywalking<\/title>"
			]
		},
		"SONICWALL-SSL-VPN": {
			"headers": {
				"server": "sonicwall ssl-vpn"
			}
		},
		"Supervisor": {
			"html": [
				"<title>supervisor status<\/title>"
			]
		},
		"TamronOS-IPTV": {
			"html": [
				"<title>tamronos iptv系统<\/title>"
			]
		},
		"TensorBoard": {
			"html": [
				"<title>tensorboard<\/title>"
			]
		},
		"ThinkAdmin": {
			"html": [
				"\/static\/theme\/img\/login\/bg1.jpg,\/static\/theme\/img\/login\/bg2.jpg"
			]
		},
		"ThinkCMF": {
			"headers": {
				"x-powered-by": "thinkcmf"
			}
		},
		"YouPHPTube": {
			"html": [
				"<title>install youphptube<\/title>",
				"youphptube streamer site"
			]
		},
		"YunGouCMS": {
			"html": [
				"statics\/templates\/yungou\/"
			]
		},
		"ZeroShell": {
			"html": [
				"<title>zeroshell<\/title>"
			]
		},
		"Citrix": {
			"html": [
				"<title>citrix login<\/title>"
			]
		},
		"weaver-ebridge": {
			"html": [
				"wx.weaver",
				"e-bridge"
			]
		},
		"TongDa": {
			"html": [
				"通达oa",
				"\/images\/tongda.ico",
				"office anywhere"
			]
		},
		"网御 vpn": {
			"html": [
				"\/vpn\/common\/js\/leadsec.js",
				"\/vpn\/user\/common\/custom\/auth_home.css"
			]
		},
		"Typecho": {
			"html": [
				"typecho",
				"generator\" content=\"typecho"
			],
			"meta": {
				"generator": [
					"typecho( [\\d.]+)?"
				]
			},
			"js": [
				"typechocomment"
			],
			"implies": [
				"PHP"
			]
		},
		"Landray": {
			"html": [
				"蓝凌软件",
				"app_themes\/login",
				"sys\/ui\/extend\/theme\/default\/style\/icon.css",
				"sys\/ui\/extend\/theme\/default\/style\/profile.css"
			]
		},
		"深信服上网行为管理系统": {
			"html": [
				"utccjfaewjb = function(str, key)",
				"document.write(wrfwwcsfbxmigkrkhxfj"
			]
		},
		"深信服应用交付报表系统": {
			"html": [
				"\/reportcenter\/index.php?cls_mode=cluster_mode_others"
			]
		},
		"金蝶云星空": {
			"html": [
				"\/clientbin\/kingdee.bos.xpf.app.xap",
				"html5\/content\/themes\/kdcss.min.css"
			]
		},
		"启明星辰天清汉马USG防火墙": {
			"html": [
				"天清汉马usg",
				"\/cgi-bin\/webui?op=get_product_model"
			]
		},
		"宝塔": {
			"html": [
				"没有找到站点",
				"入口校验失败",
				"<title>恭喜，站点创建成功",
				"宝塔",
				"bt.cn"
			],
			"implies": [
				"PHP",
				"bt"
			]
		},
		"zentao": {
			"headers": {
				"cookie": "zentaosid"
			},
			"html": [
				"zentao",
				"\/theme\/default\/images\/main\/zt-logo.png"
			]
		},
		"yonyou": {
			"html": [
				"ufida software co.ltd all rights reserved"
			]
		},
		"ZabbixSAML": {
			"html": [
				"sign in with single sign-on"
			]
		},
		"Zabbix": {
			"meta": {
				"author": [
					"zabbix sia"
				]
			},
			"js": [
				"zbxcallpostscripts"
			],
			"implies": [
				"PHP"
			],
			"html": [
				"zabbix",
				"<body[^>]+zbxcallpostscripts"
			]
		},
		"BugSnag": {
			"js": [
				"bugsnag",
				"bugsnagclient",
				"bugsnag"
			]
		},
		"Ember.js": {
			"implies": [
				"Handlebars"
			],
			"js": [
				"ember.version",
				"ember"
			]
		},
		"Matomo Tag Manager": {
			"js": [
				"matomotagmanager"
			]
		},
		"Plotly": {
			"implies": [
				"D3"
			],
			"js": [
				"plotly.version"
			]
		},
		"mini_httpd": {
			"headers": {
				"server": "mini_httpd(?:\/([\\d.]+))?"
			}
		},
		"ClickFunnels": {
			"html": [
				"<meta property=\"cf:app_domain\" content=\"app\\.clickfunnels\\.com\""
			]
		},
		"Python": {
			"headers": {
				"server": "(?:^|\\s)python(?:\/([\\d.]+))?"
			}
		},
		"Mojolicious": {
			"headers": {
				"server": "^mojolicious",
				"x-powered-by": "mojolicious"
			},
			"implies": [
				"Perl"
			]
		},
		"Microsoft Publisher": {
			"meta": {
				"generator": [
					"microsoft publisher( [\\d.]+)?"
				],
				"progid": [
					"^publisher\\."
				]
			},
			"html": [
				"(?:<html [^>]*xmlns:w=\"urn:schemas-microsoft-com:office:publisher\"|<!--[if pub]><xml>)"
			]
		},
		"Get Satisfaction": {
			"js": [
				"gsfn"
			]
		},
		"Fireblade": {
			"headers": {
				"server": "fbs"
			}
		},
		"Piano": {
			"js": [
				"pianoespconfig",
				"gcidatapiano"
			]
		},
		"Xonic": {
			"meta": {
				"keywords": [
					"xonic-solutions"
				]
			},
			"html": [
				"powered by <a href=\"http:\/\/www\\.xonic-solutions\\.de\/index\\.php\" target=\"_blank\">xonic-solutions shopsoftware<\/a>"
			]
		},
		"NTLM": {
			"headers": {
				"www-authenticate": "^ntlm"
			}
		},
		"Svelte": {
			"html": [
				"<[^>]+class=\\\"[^\\\"]+\\ssvelte-[\\w]*\\\""
			]
		},
		"vibecommerce": {
			"meta": {
				"generator": [
					"vibecommerce"
				],
				"designer": [
					"vibecommerce"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"RD Station": {
			"js": [
				"rdstation"
			]
		},
		"Rakuten Digital Commerce": {
			"js": [
				"rakutenapplication"
			]
		},
		"Big Cartel": {
			"meta": {
				"generator": [
					"big cartel"
				]
			}
		},
		"Clicky": {
			"js": [
				"clicky"
			]
		},
		"List.js": {
			"js": [
				"list"
			]
		},
		"DocFX": {
			"meta": {
				"generator": [
					"docfx\\s([\\d\\.]+)"
				],
				"docfx:tocrel": [
					"toc.html"
				],
				"docfx:navrel": [
					"toc.html"
				]
			}
		},
		"Birdeye": {
			"js": [
				"bfiframe"
			]
		},
		"Lede": {
			"meta": {
				"og:image": [
					"https?\\:\\\/\\\/lede-admin"
				]
			},
			"js": [
				"ledechartbeatviews",
				"ledeengagement",
				"ledeengagementreset"
			],
			"implies": [
				"WordPress",
				"WordPress VIP"
			],
			"html": [
				"<a [^>]*href=\"[^\"]+joinlede.com"
			]
		},
		"Yahoo! Tag Manager": {
			"html": [
				"<!-- (?:end )?yahoo! tag manager -->"
			]
		},
		"IdoSell Shop": {
			"js": [
				"iai_ajax"
			]
		},
		"Livewire": {
			"implies": [
				"Laravel"
			],
			"js": [
				"livewire"
			],
			"html": [
				"<[^>]{1,512}\\bwire:"
			]
		},
		"Aweber": {
			"js": [
				"awt_analytics"
			]
		},
		"Convert": {
			"js": [
				"convert",
				"convertdata",
				"convert_temp"
			]
		},
		"Outbrain": {
			"js": [
				"ob_releasever",
				"outbrainpermalink"
			]
		},
		"PDF.js": {
			"js": [
				"pdfjsdistbuildpdf.version",
				"pdfjslib.version",
				"pdfjs",
				"pdfjs.version",
				"_pdfjscompatibilitychecked",
				"pdfjs-dist\/build\/pdf.version"
			],
			"html": [
				"<\\\/div>\\s*<!-- outercontainer -->\\s*<div\\s*id=\"printcontainer\"><\\\/div>"
			]
		},
		"Nginx": {
			"headers": {
				"server": "nginx(?:\/([\\d.]+))?",
				"x-fastcgi-cache": ""
			}
		},
		"Jibres": {
			"cookies": {
				"jibres": ""
			},
			"meta": {
				"generator": [
					"jibres"
				]
			},
			"js": [
				"jibres"
			],
			"headers": {
				"x-powered-by": "jibres"
			}
		},
		"CouchDB": {
			"headers": {
				"server": "couchdb\/([\\d.]+)"
			}
		},
		"Magento": {
			"cookies": {
				"frontend": ""
			},
			"js": [
				"mage",
				"varienform"
			],
			"implies": [
				"PHP",
				"MySQL"
			],
			"html": [
				"<script [^>]+data-requiremodule=\"mage\/",
				"<script [^>]+data-requiremodule=\"magento_",
				"<script type=\"text\/x-magento-init\">"
			]
		},
		"Actito": {
			"cookies": {
				"smartfocus": ""
			},
			"js": [
				"smartfocus",
				"_actgoal"
			]
		},
		"MediaWiki": {
			"meta": {
				"generator": [
					"^mediawiki ?(.+)$"
				]
			},
			"js": [
				"mw.util.toggletoc",
				"wgtitle",
				"wgversion"
			],
			"implies": [
				"PHP"
			],
			"html": [
				"<body[^>]+class=\"mediawiki\"",
				"<(?:a|img)[^>]+>powered by mediawiki<\/a>",
				"<a[^>]+\/special:whatlinkshere\/"
			]
		},
		"Carbon Ads": {
			"js": [
				"_carbonads"
			],
			"html": [
				"<[a-z]+ [^>]*id=\"carbonads-container\""
			]
		},
		"experiencedCMS": {
			"meta": {
				"generator": [
					"^experiencedcms$"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"Winstone Servlet Container": {
			"headers": {
				"x-powered-by": "winstone(?:\\\/([\\d.]+))?",
				"server": "winstone servlet (?:container|engine) v?([\\d.]+)?"
			}
		},
		"InstantCMS": {
			"cookies": {
				"instantcms[logdate]": ""
			},
			"meta": {
				"generator": [
					"instantcms"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"Po.st": {
			"js": [
				"pwidget_config"
			]
		},
		"Smarter Click": {
			"js": [
				"$smcinstall",
				"$smct5",
				"$smctdata"
			]
		},
		"Nette Framework": {
			"cookies": {
				"nette-browser": ""
			},
			"js": [
				"nette",
				"nette.version"
			],
			"headers": {
				"x-powered-by": "^nette framework"
			},
			"html": [
				"<input[^>]+data-nette-rules",
				"<div[^>]+id=\"snippet-",
				"<input[^>]+id=\"frm-"
			],
			"implies": [
				"PHP"
			]
		},
		"ZK": {
			"implies": [
				"Java"
			],
			"html": [
				"<!-- zk [.\\d\\s]+-->"
			]
		},
		"total.js": {
			"headers": {
				"x-powered-by": "^total\\.js"
			},
			"implies": [
				"Node.js"
			]
		},
		"T-Soft": {
			"html": [
				"<a href=\"http:\/\/www\\.tsoft\\.com\\.tr\" target=\"_blank\" title=\"t-soft e-ticaret sistemleri\">"
			]
		},
		"GoStats": {
			"js": [
				"_gostatsrun",
				"_go_track_src",
				"go_msie"
			]
		},
		"Aplazame": {
			"js": [
				"aplazame"
			]
		},
		"FaraPy": {
			"implies": [
				"Python"
			],
			"html": [
				"<!-- powered by farapy."
			]
		},
		"Ant Design": {
			"js": [
				"antd"
			],
			"html": [
				"<[^>]*class=\"ant-(?:btn|col|row|layout|breadcrumb|menu|pagination|steps|select|cascader|checkbox|calendar|form|input-number|input|mention|rate|radio|slider|switch|tree-select|time-picker|transfer|upload|avatar|badge|card|carousel|collapse|list|popover|tooltip|table|tabs|tag|timeline|tree|alert|modal|message|notification|progress|popconfirm|spin|anchor|back-top|divider|drawer)",
				"<i class=\"anticon anticon-"
			]
		},
		"Amplitude": {
			"js": [
				"amplitude_key"
			]
		},
		"OneAll": {
			"js": [
				"oa_social_login"
			]
		},
		"Drupal": {
			"meta": {
				"generator": [
					"^drupal(?:\\s([\\d.]+))?"
				]
			},
			"js": [
				"drupal"
			],
			"headers": {
				"expires": "19 nov 1978",
				"x-drupal-cache": ""
			},
			"html": [
				"<(?:link|style)[^>]+\"\/sites\/(?:default|all)\/(?:themes|modules)\/"
			],
			"implies": [
				"PHP"
			]
		},
		"G-WAN": {
			"headers": {
				"server": "g-wan"
			}
		},
		"PHPFusion": {
			"headers": {
				"x-powered-by": "phpfusion (.+)$",
				"x-phpfusion": "(.+)$"
			},
			"html": [
				"powered by <a href=\"[^>]+phpfusion",
				"powered by <a href=\"[^>]+php-fusion"
			],
			"implies": [
				"PHP",
				"MySQL"
			]
		},
		"WooCommerce": {
			"meta": {
				"generator": [
					"woocommerce ([\\d.]+)"
				]
			},
			"js": [
				"woocommerce_params"
			],
			"implies": [
				"WordPress"
			],
			"html": [
				"<!-- woocommerce",
				"<link rel='[^']+' id='woocommerce-(?:layout|smallscreen|general)-css'  href='https?:\/\/[^\/]+\/wp-content\/plugins\/woocommerce\/assets\/css\/woocommerce(?:-layout|-smallscreen)?\\.css?ver=([\\d.]+)'"
			]
		},
		"AB Tasty": {
			"js": [
				"loadabtasty",
				"abtasty",
				"_abtasty"
			]
		},
		"CMS Made Simple": {
			"cookies": {
				"cmssessid": ""
			},
			"meta": {
				"generator": [
					"cms made simple"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"Voog.com Website Builder": {
			"html": [
				"<script [^>]*src=\"[^\"]*voog\\.com\/tracker\\.js"
			]
		},
		"Corebine": {
			"js": [
				"corebine"
			]
		},
		"PlatformOS": {
			"headers": {
				"x-powered-by": "^platformos$"
			}
		},
		"Pinterest Conversion Tag": {
			"js": [
				"pintrk"
			]
		},
		"StackPath": {
			"headers": {
				"x-backend-server": "hosting\\.stackcp\\.net$",
				"x-provided-by": "^stackcdn(?: ([\\d.]+))?"
			}
		},
		"Linkedin Insight Tag": {
			"js": [
				"_linkedin_data_partner_id"
			]
		},
		"SharpSpring": {
			"js": [
				"sharpspring_tracking_installed"
			]
		},
		"GeneXus": {
			"js": [
				"gx.gxversion"
			],
			"html": [
				"<link[^>]+?id=\"gxtheme_css_reference\""
			]
		},
		"Ahoy": {
			"cookies": {
				"ahoy_track": ""
			},
			"js": [
				"ahoy"
			]
		},
		"Simplébo": {
			"headers": {
				"x-servedby": "simplebo"
			}
		},
		"RBS Change": {
			"meta": {
				"generator": [
					"rbs change"
				]
			},
			"html": [
				"<html[^>]+xmlns:change="
			],
			"implies": [
				"PHP"
			]
		},
		"Blackbaud Luminate Online": {
			"js": [
				"don_premium_map"
			]
		},
		"ContentBox": {
			"meta": {
				"generator": [
					"contentbox powered by coldbox"
				]
			},
			"implies": [
				"Adobe ColdFusion"
			]
		},
		"Gauges": {
			"cookies": {
				"_gauges_": ""
			},
			"js": [
				"_gauges"
			]
		},
		"Plausible": {
			"js": [
				"plausible"
			]
		},
		"Coaster CMS": {
			"meta": {
				"generator": [
					"^coaster cms v([\\d.]+)$"
				]
			},
			"implies": [
				"Laravel"
			]
		},
		"LKQD": {
			"js": [
				"lkqdcall",
				"lkqderrorcount",
				"lkqdsettings",
				"lkqd_http_response"
			]
		},
		"Reinvigorate": {
			"js": [
				"reinvigorate"
			]
		},
		"Meteor": {
			"implies": [
				"MongoDB",
				"Node.js"
			],
			"js": [
				"meteor",
				"meteor.release"
			],
			"html": [
				"<link[^>]+__meteor-css__"
			]
		},
		"Materialize CSS": {
			"html": [
				"<link[^>]* href=\"[^\"]*materialize(?:\\.min)?\\.css"
			]
		},
		"Splitbee": {
			"js": [
				"splitbee"
			]
		},
		"Jetshop": {
			"js": [
				"jetshopdata"
			],
			"html": [
				"<(?:div|aside) id=\"jetshop-branding\">"
			]
		},
		"UserRules": {
			"js": [
				"_usrp"
			]
		},
		"Sivuviidakko": {
			"meta": {
				"generator": [
					"sivuviidakko"
				]
			}
		},
		"Polymer": {
			"js": [
				"polymer.version"
			],
			"html": [
				"(?:<polymer-[^>]+|<link[^>]+rel=\"import\"[^>]+\/polymer\\.html\")"
			]
		},
		"NSW Design System": {
			"js": [
				"nsw.initsite"
			]
		},
		"otrs": {
			"headers": {
				"x-powered-by": "otrs ([\\d.]+)"
			},
			"html": [
				"<!--\\s+otrs: copyright"
			],
			"implies": [
				"Perl"
			]
		},
		"GrandNode": {
			"cookies": {
				"grand.customer": ""
			},
			"meta": {
				"generator": [
					"grandnode"
				]
			},
			"implies": [
				"Microsoft ASP.NET"
			],
			"html": [
				"(?:<!--grandnode |<a[^>]+grandnode - powered by |powered by: <a[^>]+nopcommerce)"
			]
		},
		"GOV.UK Frontend": {
			"js": [
				"govukfrontend"
			],
			"html": [
				"<link[^>]* href=[^>]*?govuk-frontend(?:[^>]*?([0-9a-fa-f]{7,40}|[\\d]+(?:.[\\d]+(?:.[\\d]+)?)?)|)[^>]*?(?:\\.min)?\\.css",
				"<body[^>]+govuk-template__body",
				"<a[^>]+govuk-link"
			]
		},
		"CS Cart": {
			"implies": [
				"PHP"
			],
			"js": [
				"fn_compare_strings"
			],
			"html": [
				"&nbsp;powered by (?:<a href=[^>]+cs-cart\\.com|cs-cart)",
				"\\.cm-noscript[^>]+<\/style>"
			]
		},
		"nopCommerce": {
			"cookies": {
				"nop.customer": ""
			},
			"meta": {
				"generator": [
					"^nopcommerce$"
				]
			},
			"implies": [
				"Microsoft ASP.NET"
			],
			"html": [
				"(?:<!--powered by nopcommerce|powered by: <a[^>]+nopcommerce)"
			]
		},
		"Ezoic": {
			"js": [
				"ezoica",
				"ezoicbanger",
				"ezoictestactive"
			]
		},
		"YouTrack": {
			"html": [
				"no-title=\"youtrack\">",
				"data-reactid=\"[^\"]+\">youtrack ([0-9.]+)<",
				"type=\"application\/opensearchdescription\\+xml\" title=\"youtrack\"\/>"
			]
		},
		"Bizweb": {
			"js": [
				"bizweb"
			]
		},
		"BOOM": {
			"headers": {
				"x-supplied-by": "mana"
			},
			"meta": {
				"generator": [
					"^boom site builder$"
				]
			},
			"implies": [
				"WordPress"
			]
		},
		"Eveve": {
			"implies": [
				"PHP"
			],
			"html": [
				"<iframe[^>]*[\\w]+\\.eveve\\.com"
			]
		},
		"Contenido": {
			"meta": {
				"generator": [
					"contenido ([\\d.]+)"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"Plone": {
			"meta": {
				"generator": [
					"plone"
				]
			},
			"implies": [
				"Python"
			]
		},
		"Google Cloud Storage": {
			"headers": {
				"x-goog-storage-class": "^\\w+$"
			},
			"implies": [
				"Google Cloud"
			]
		},
		"FareHarbor": {
			"html": [
				"<iframe[^>]+fareharbor"
			]
		},
		"Akka HTTP": {
			"headers": {
				"server": "akka-http(?:\/([\\d.]+))?"
			}
		},
		"Mynetcap": {
			"meta": {
				"generator": [
					"mynetcap"
				]
			}
		},
		"WebGUI": {
			"cookies": {
				"wgsession": ""
			},
			"meta": {
				"generator": [
					"^webgui ([\\d.]+)"
				]
			},
			"implies": [
				"Perl"
			]
		},
		"Atlassian Statuspage": {
			"headers": {
				"x-statuspage-skip-logging": ""
			},
			"html": [
				"<a[^>]*href=\"https?:\/\/(?:www\\.)?statuspage\\.io\/powered-by[^>]+>"
			]
		},
		"New Relic": {
			"js": [
				"nreum",
				"newrelic"
			]
		},
		"MkDocs": {
			"meta": {
				"generator": [
					"^mkdocs-([\\d.]+)"
				]
			}
		},
		"Bread": {
			"js": [
				"breadcalc",
				"breaderror",
				"breadloaded",
				"breadshopify",
				"bread.apphost"
			]
		},
		"DigitalRiver": {
			"cookies": {
				"x-dr-shopper-ets": ""
			}
		},
		"MantisBT": {
			"implies": [
				"PHP"
			],
			"html": [
				"<img[^>]+ alt=\"powered by mantis bugtracker"
			]
		},
		"Redis Object Cache": {
			"implies": [
				"Redis",
				"WordPress"
			],
			"html": [
				"<!--\\s+performance optimized by redis object cache"
			]
		},
		"CodeMirror": {
			"js": [
				"codemirror",
				"codemirror.version"
			]
		},
		"SquirrelMail": {
			"implies": [
				"PHP"
			],
			"js": [
				"squirrelmail_loginpage_onload"
			],
			"html": [
				"<small>squirrelmail version ([.\\d]+)[^<]*<br "
			]
		},
		"Yottaa": {
			"meta": {
				"x-yottaa-optimizations": [

				],
				"x-yottaa-metrics": [

				]
			}
		},
		"Clarity": {
			"implies": [
				"Angular"
			],
			"js": [
				"clarityicons"
			],
			"html": [
				"<clr-main-container",
				"<link [^>]*href=\"[^\"]*clr-ui(?:\\.min)?\\.css"
			]
		},
		"Bokeh": {
			"implies": [
				"Python"
			],
			"js": [
				"bokeh",
				"bokeh.version"
			]
		},
		"Planet": {
			"meta": {
				"generator": [
					"^planet(?:\/([\\d.]+))?"
				]
			}
		},
		"My Food Link": {
			"html": [
				"<div class='mfl-made-by-myfoodlink'>",
				"<a href=\"https:\/\/www.myfoodlink.com.au"
			]
		},
		"Webzi": {
			"meta": {
				"generator": [
					"^webzi"
				]
			},
			"js": [
				"webzi"
			]
		},
		"Seravo": {
			"headers": {
				"x-powered-by": "^seravo"
			},
			"implies": [
				"WordPress"
			]
		},
		"XWiki": {
			"meta": {
				"wiki": [
					"xwiki"
				]
			},
			"html": [
				"<html[^>]data-xwiki-[^>]>"
			],
			"implies": [
				"Java"
			]
		},
		"Flat UI": {
			"implies": [
				"Bootstrap"
			],
			"html": [
				"<link[^>]* href=[^>]+flat-ui(?:\\.min)?\\.css"
			]
		},
		"CDN77": {
			"headers": {
				"server": "^cdn77-turbo$"
			}
		},
		"SUSE": {
			"headers": {
				"server": "suse(?:\/?\\s?-?([\\d.]+))?",
				"x-powered-by": "suse(?:\/?\\s?-?([\\d.]+))?"
			}
		},
		"AfterBuy": {
			"html": [
				"<dd>this onlinestore is brought to you by via-online gmbh afterbuy\\. information and contribution at https:\/\/www\\.afterbuy\\.de<\/dd>"
			]
		},
		"Spree": {
			"implies": [
				"Ruby on Rails"
			],
			"html": [
				"(?:<link[^>]*\/assets\/store\/all-[a-z\\d]{32}\\.css[^>]+>|<script>\\s*spree\\.(?:routes|translations|api_key))"
			]
		},
		"Nepso": {
			"headers": {
				"x-powered-cms": "nepso"
			}
		},
		"jQuery UI": {
			"implies": [
				"jQuery"
			],
			"js": [
				"jquery.ui.version"
			]
		},
		"Facebook Pixel": {
			"js": [
				"_fbq"
			]
		},
		"Zonos": {
			"js": [
				"zonoscheckout",
				"zonos",
				"zonos"
			]
		},
		"MochiWeb": {
			"headers": {
				"server": "mochiweb(?:\/([\\d.]+))?"
			}
		},
		"Squarespace Commerce": {
			"implies": [
				"Squarespace"
			],
			"js": [
				"squarespace_rollups.squarespace-commerce",
				"squarespacecommercecartbundle"
			]
		},
		"Resin": {
			"headers": {
				"server": "^resin(?:\/(\\s*))?"
			},
			"implies": [
				"Java"
			]
		},
		"lighttpd": {
			"headers": {
				"server": "lighttpd(?:\/([\\d.]+))?"
			}
		},
		"eClass": {
			"js": [
				"fe_eclass",
				"fe_eclass_guest"
			]
		},
		"Pixlee": {
			"js": [
				"pixlee",
				"pixlee_analytics"
			]
		},
		"Bloomreach Search & Merchandising": {
			"js": [
				"br_data",
				"brtrk"
			]
		},
		"Frontity": {
			"meta": {
				"generator": [
					"^frontity"
				]
			},
			"implies": [
				"React",
				"webpack",
				"WordPress"
			]
		},
		"eZ Publish": {
			"cookies": {
				"ezsessid": ""
			},
			"meta": {
				"generator": [
					"ez publish"
				]
			},
			"headers": {
				"x-powered-by": "^ez publish"
			},
			"implies": [
				"PHP"
			]
		},
		"Welcart": {
			"cookies": {
				"usces_cookie": ""
			},
			"html": [
				"<link[^>]+?href=\"[^\"]+usces_default(?:\\.min)?\\.css",
				"<!-- welcart version : v([\\d.]+)"
			],
			"implies": [
				"PHP",
				"WordPress"
			]
		},
		"Adobe Analytics": {
			"js": [
				"s_c_il.0._c",
				"s_c_il.2._c",
				"s_c_il.3._c",
				"s_c_il.3.constructor.name",
				"s_c_il.4._c",
				"s_c_il.5.constructor.name",
				"s_c_il.0.constructor.name",
				"s_c_il.1._c",
				"s_c_il.1.constructor.name",
				"s_c_il.2.constructor.name",
				"s_c_il.4.constructor.name",
				"s_c_il.5._c"
			]
		},
		"Neos CMS": {
			"headers": {
				"x-flow-powered": "neos\/?(.+)?$"
			},
			"implies": [
				"Neos Flow"
			]
		},
		"JivoChat": {
			"js": [
				"jivo_api",
				"jivo_version"
			]
		},
		"Intercom": {
			"js": [
				"intercom"
			]
		},
		"phpCMS": {
			"implies": [
				"PHP"
			],
			"js": [
				"phpcms"
			]
		},
		"AddToAny": {
			"js": [
				"a2apage_init"
			]
		},
		"wpCache": {
			"meta": {
				"generator": [
					"wpcache"
				],
				"keywords": [
					"wpcache"
				]
			},
			"headers": {
				"x-powered-by": "wpcache(?:\/([\\d.]+))?"
			},
			"implies": [
				"WordPress",
				"PHP"
			],
			"html": [
				"<!--[^>]+wpcache"
			]
		},
		"Marionette.js": {
			"implies": [
				"Underscore.js",
				"Backbone.js"
			],
			"js": [
				"marionette",
				"marionette.version"
			]
		},
		"Fastspring": {
			"html": [
				"<a [^>]*href=\"https?:\/\/sites\\.fastspring\\.com",
				"<form [^>]*action=\"https?:\/\/sites\\.fastspring\\.com"
			]
		},
		"@sulu\/web": {
			"js": [
				"web.startcomponents"
			]
		},
		"Izooto": {
			"js": [
				"izooto",
				"_izooto"
			]
		},
		"Loox": {
			"js": [
				"loox_global_hash"
			]
		},
		"Banshee": {
			"meta": {
				"generator": [
					"banshee php"
				]
			},
			"html": [
				"built upon the <a href=\"[^>]+banshee-php\\.org\/\">[a-z]+<\/a>(?:v([\\d.]+))?"
			],
			"implies": [
				"PHP"
			]
		},
		"Miva": {
			"headers": {
				"content-disposition": "filename=(?:mvga\\.js|mivaevents\\.js)"
			},
			"js": [
				"mivajs.screen",
				"mivajs.store_code",
				"mivavm_api",
				"mivavm_version",
				"mivajs",
				"mivajs.page",
				"mivajs.product_code",
				"mivajs.product_id"
			]
		},
		"TakeDrop": {
			"js": [
				"webpackjsonptakedrop-react"
			]
		},
		"Fortune3": {
			"html": [
				"(?:<link [^>]*href=\"[^\\\/]*\\\/\\\/www\\.fortune3\\.com\\\/[^\"]*siterate\\\/rate\\.css|powered by <a [^>]*href=\"[^\"]+fortune3\\.com)"
			]
		},
		"Store Systems": {
			"html": [
				"shopsystem von <a href=[^>]+store-systems\\.de\""
			]
		},
		"AMP Plugin": {
			"meta": {
				"generator": [
					"^amp plugin v(\\d+\\.\\d+.*)$"
				]
			},
			"implies": [
				"WordPress"
			]
		},
		"K2": {
			"implies": [
				"Joomla"
			],
			"js": [
				"k2ratingurl"
			],
			"html": [
				"<!--(?: joomlaworks \"k2\"| start k2)"
			]
		},
		"Websocket": {
			"html": [
				"<link[^>]+rel=[\"']web-socket[\"']",
				"<(?:link|a)[^>]+href=[\"']wss?:\/\/"
			]
		},
		"RedCart": {
			"cookies": {
				"rc2c-erotica": "\\d+"
			},
			"js": [
				"rc_shop_id"
			]
		},
		"RX Web Server": {
			"headers": {
				"x-powered-by": "rx-web"
			}
		},
		"Public CMS": {
			"cookies": {
				"publiccms_user": ""
			},
			"headers": {
				"x-powered-publiccms": "^(.+)$"
			},
			"implies": [
				"Java"
			]
		},
		"Miresoone": {
			"meta": {
				"generator": [
					"^miresoone"
				]
			},
			"implies": [
				"Laravel",
				"React"
			]
		},
		"Admitad": {
			"js": [
				"admitad",
				"admitad"
			]
		},
		"OroCommerce": {
			"implies": [
				"PHP",
				"MySQL"
			],
			"html": [
				"<script [^>]+data-requiremodule=\"oro\/",
				"<script [^>]+data-requiremodule=\"oroui\/"
			]
		},
		"Webgains": {
			"js": [
				"itclkq"
			]
		},
		"Percussion": {
			"meta": {
				"generator": [
					"(?:percussion|rhythmyx)"
				]
			},
			"html": [
				"<[^>]+class=\"perc-region\""
			]
		},
		"Epoch": {
			"implies": [
				"D3"
			],
			"html": [
				"<link[^>]+?href=\"[^\"]+epoch(?:\\.min)?\\.css"
			]
		},
		"Cotonti": {
			"meta": {
				"generator": [
					"cotonti"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"Yandex.Messenger": {
			"js": [
				"yandexchatwidget"
			]
		},
		"Pipedrive": {
			"js": [
				"leadbooster"
			]
		},
		"ELOG HTTP": {
			"headers": {
				"server": "elog http ?([\\d.-]+)?"
			},
			"implies": [
				"ELOG"
			]
		},
		"Quill": {
			"js": [
				"quill"
			]
		},
		"Modified": {
			"meta": {
				"generator": [
					"\\(c\\) by modified ecommerce shopsoftware ------ http:\/\/www\\.modified-shop\\.org"
				]
			}
		},
		"Websale": {
			"cookies": {
				"websale_ac": ""
			}
		},
		"Bolt Payments": {
			"js": [
				"bolt_callbacks",
				"boltcheckout"
			]
		},
		"OXID eShop Enterprise Edition": {
			"implies": [
				"PHP"
			],
			"html": [
				"<!--[^-]*oxid eshop enterprise edition, version (\\d+)"
			]
		},
		"SiteEdit": {
			"meta": {
				"generator": [
					"siteedit"
				]
			}
		},
		"Phoenix": {
			"meta": {
				"generator": [
					"^phoenix"
				]
			},
			"js": [
				"phoenix"
			],
			"implies": [
				"React",
				"webpack",
				"Node.js"
			]
		},
		"Reddit": {
			"implies": [
				"Python"
			],
			"js": [
				"reddit"
			],
			"html": [
				"(?:<a[^>]+powered by reddit|powered by <a[^>]+>reddit<)"
			]
		},
		"KobiMaster": {
			"implies": [
				"Microsoft ASP.NET"
			],
			"js": [
				"kmgetsession",
				"kmpageinfo"
			]
		},
		"WordPress VIP": {
			"headers": {
				"x-powered-by": "^wordpress\\.com vip"
			},
			"implies": [
				"WordPress",
				"Automattic"
			]
		},
		"GX WebManager": {
			"meta": {
				"generator": [
					"gx webmanager(?: ([\\d.]+))?"
				]
			},
			"html": [
				"<!--\\s+powered by gx"
			]
		},
		"HeadJS": {
			"js": [
				"head.browser.name"
			],
			"html": [
				"<[^>]*data-headjs-load"
			]
		},
		"Ushahidi": {
			"cookies": {
				"ushahidi": ""
			},
			"js": [
				"ushahidi"
			],
			"implies": [
				"PHP",
				"MySQL",
				"OpenLayers"
			]
		},
		"Automattic": {
			"headers": {
				"x-hacker": "(?:automattic\\.com\/jobs|wpvip\\.com\/careers)"
			},
			"implies": [
				"WordPress"
			]
		},
		"Alpine.js": {
			"js": [
				"alpine.version"
			],
			"html": [
				"<[^>]+[^\\w-]x-data[^\\w-][^<]+"
			]
		},
		"Highstock": {
			"html": [
				"<svg[^>]*><desc>created with highstock ([\\d.]*)"
			]
		},
		"Prefix-Free": {
			"js": [
				"prefixfree"
			]
		},
		"Act-On": {
			"js": [
				"acton"
			]
		},
		"Mambo": {
			"meta": {
				"generator": [
					"mambo"
				]
			}
		},
		"HelpDocs": {
			"js": [
				"hdanalytics",
				"hdutils",
				"hd_instant_search"
			]
		},
		"Incapsula": {
			"headers": {
				"x-cdn": "incapsula"
			}
		},
		"Asciinema": {
			"js": [
				"asciinema"
			],
			"html": [
				"<asciinema-player"
			]
		},
		"Indexhibit": {
			"meta": {
				"generator": [
					"indexhibit"
				]
			},
			"html": [
				"<(?:link|a href) [^>]+ndxz-studio"
			],
			"implies": [
				"PHP",
				"Apache",
				"Exhibit"
			]
		},
		"OpenResty": {
			"headers": {
				"server": "openresty(?:\/([\\d.]+))?"
			},
			"implies": [
				"Nginx"
			]
		},
		"FreeTextBox": {
			"implies": [
				"Microsoft ASP.NET"
			],
			"js": [
				"ftb_api",
				"ftb_addevent"
			],
			"html": [
				"<!-- \\* freetextbox v\\d \\((\\d+\\.\\d+\\.\\d+)"
			]
		},
		"Movable Type": {
			"meta": {
				"generator": [
					"movable type"
				]
			}
		},
		"Ruby Receptionists": {
			"js": [
				"rubyapi"
			]
		},
		"Dotclear": {
			"headers": {
				"x-dotclear-static-cache": ""
			},
			"implies": [
				"PHP"
			]
		},
		"AT Internet Analyzer": {
			"js": [
				"atinternet",
				"xtsite"
			]
		},
		"Mozard Suite": {
			"meta": {
				"author": [
					"mozard"
				]
			}
		},
		"JBoss": {
			"headers": {
				"x-powered-by": "jboss(?:-([\\d.]+))?"
			},
			"html": [
				"jboss.css"
			]
		},
		"CoconutSoftware": {
			"cookies": {
				"coconut_calendar": ""
			}
		},
		"Gravity Forms": {
			"implies": [
				"WordPress"
			],
			"html": [
				"<div class=(?:\"|')[^>]*gform_wrapper",
				"<div class=(?:\"|')[^>]*gform_body",
				"<ul [^>]*class=(?:\"|')[^>]*gform_fields",
				"<link [^>]*href=(?:\"|')[^>]*wp-content\/plugins\/gravityforms\/css\/"
			]
		},
		"three.js": {
			"js": [
				"three.revision"
			]
		},
		"Digest": {
			"headers": {
				"www-authenticate": "^digest"
			}
		},
		"PencilBlue": {
			"headers": {
				"x-powered-by": "pencilblue"
			},
			"implies": [
				"Node.js"
			]
		},
		"Adobe GoLive": {
			"meta": {
				"generator": [
					"adobe golive(?:\\s([\\d.]+))?"
				]
			}
		},
		"Mondo Media": {
			"meta": {
				"generator": [
					"mondo shop"
				]
			}
		},
		"Confluence": {
			"headers": {
				"x-confluence-request-time": ""
			},
			"meta": {
				"confluence-request-time": [

				]
			},
			"implies": [
				"Java"
			]
		},
		"SummerCart": {
			"implies": [
				"PHP"
			],
			"js": [
				"sc",
				"scevents"
			]
		},
		"Milligram": {
			"html": [
				"<link[^>]+?href=\"[^\"]+milligram(?:\\.min)?\\.css"
			]
		},
		"PayBright": {
			"js": [
				"_paybright_config"
			]
		},
		"Tidio": {
			"js": [
				"tidiochatapi"
			]
		},
		"Pardot": {
			"headers": {
				"x-pardot-lb": ""
			},
			"js": [
				"piaid",
				"picid",
				"pihostname",
				"piprotocol",
				"pitracker"
			]
		},
		"Voracio": {
			"cookies": {
				"voracio_csrf_token": ""
			},
			"js": [
				"voracio"
			]
		},
		"Inertia": {
			"headers": {
				"x-inertia": ""
			}
		},
		"Amazon Web Services": {
			"headers": {
				"x-amz-delete-marker": ""
			}
		},
		"Axios": {
			"js": [
				"axios.get"
			]
		},
		"Leaflet": {
			"js": [
				"l.distancegrid",
				"l.posanimation",
				"l.version"
			]
		},
		"AdThrive": {
			"js": [
				"adthrivevideosinjected",
				"adthrive"
			]
		},
		"Kohana": {
			"cookies": {
				"kohanasession": ""
			},
			"headers": {
				"x-powered-by": "kohana framework ([\\d.]+)"
			},
			"implies": [
				"PHP"
			]
		},
		"Mollom": {
			"html": [
				"<img[^>]+\\.mollom\\.com"
			]
		},
		"Mobirise": {
			"meta": {
				"generator": [
					"^mobirise v([\\d.]+)"
				]
			},
			"html": [
				"<!-- site made with mobirise website builder v([\\d.]+)"
			]
		},
		"Lodash": {
			"js": [
				"_.version",
				"_.differenceby",
				"_.templatesettings.imports._.templatesettings.imports._.version"
			]
		},
		"Awesomplete": {
			"js": [
				"awesomplete"
			],
			"html": [
				"<link[^>]+href=\"[^>]*awesomplete(?:\\.min)?\\.css"
			]
		},
		"Microsoft PowerPoint": {
			"meta": {
				"generator": [
					"microsoft powerpoint ( [\\d.]+)?"
				],
				"progid": [
					"^powerpoint\\."
				]
			},
			"html": [
				"(?:<html [^>]*xmlns:w=\"urn:schemas-microsoft-com:office:powerpoint\"|<link rel=\"?presentation-xml\"? href=\"?[^\"]+\\.xml\"?>|<o:presentationformat>[^<]+<\/o:presentationformat>[^!]+<o:slides>\\d+<\/o:slides>(?:[^!]+<o:version>([\\d.]+)<\/o:version>)?)"
			]
		},
		"Laravel": {
			"headers": {
				"set-cookie": "laravel_session",
				"cookie": "laravel_session"
			},
			"cookies": {
				"laravel_session": ""
			},
			"js": [
				"laravel"
			],
			"implies": [
				"PHP"
			]
		},
		"Jetty": {
			"headers": {
				"server": "jetty(?:\\(([\\d\\.]*\\d+))?"
			},
			"implies": [
				"Java"
			]
		},
		"Tessitura": {
			"implies": [
				"Microsoft ASP.NET",
				"IIS",
				"Windows Server"
			],
			"html": [
				"<!--[^>]+tessitura version: (\\d*\\.\\d*\\.\\d*)?"
			]
		},
		"GetSimple CMS": {
			"meta": {
				"generator": [
					"getsimple"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"LiteSpeed": {
			"headers": {
				"server": "^litespeed$"
			}
		},
		"Backdrop": {
			"meta": {
				"generator": [
					"^backdrop cms(?:\\s([\\d.]+))?"
				]
			},
			"js": [
				"backdrop"
			],
			"headers": {
				"x-backdrop-cache": ""
			},
			"implies": [
				"PHP"
			]
		},
		"Insider": {
			"js": [
				"insider"
			]
		},
		"Xtremepush": {
			"js": [
				"xtremepush"
			]
		},
		"KaTeX": {
			"js": [
				"katex",
				"katex.version"
			]
		},
		"LiveHelp": {
			"js": [
				"lhready"
			]
		},
		"Gambio": {
			"implies": [
				"PHP"
			],
			"js": [
				"gambio"
			],
			"html": [
				"(?:<link[^>]* href=\"templates\/gambio\/|<a[^>]content\\.php\\?coid=\\d|<!-- gambio eof -->|<!--[\\s=]+shopsoftware by gambio gmbh \\(c\\))"
			]
		},
		"Flask": {
			"headers": {
				"server": "werkzeug\/?([\\d\\.]+)?"
			},
			"implies": [
				"Python"
			]
		},
		"Hugo": {
			"meta": {
				"generator": [
					"hugo ([\\d.]+)?"
				]
			},
			"html": [
				"powered by <a [^>]*href=\"http:\/\/hugo\\.spf13\\.com"
			]
		},
		"YUI Doc": {
			"html": [
				"(?:<html[^>]* yuilibrary\\.com\/rdf\/[\\d.]+\/yui\\.rdf|<body[^>]+class=\"yui3-skin-sam)"
			]
		},
		"Angular": {
			"implies": [
				"TypeScript"
			],
			"js": [
				"ng.coretokens",
				"ng.probe"
			]
		},
		"LoginRadius": {
			"js": [
				"loginradius",
				"loginradiusdefaults",
				"loginradiussdk",
				"loginradiusutility"
			]
		},
		"Czater": {
			"js": [
				"$czatermethods",
				"$czater"
			]
		},
		"SharpSpring Ads": {
			"js": [
				"_pa"
			]
		},
		"React": {
			"js": [
				"react.version",
				"react.version"
			],
			"html": [
				"<[^>]+data-react"
			]
		},
		"JShop": {
			"js": [
				"jss_1stepdeliverytype",
				"jss_1stepfillshipping"
			]
		},
		"October CMS": {
			"cookies": {
				"october_session": ""
			},
			"meta": {
				"generator": [
					"octobercms"
				]
			},
			"implies": [
				"Laravel"
			]
		},
		"PhotoShelter": {
			"implies": [
				"PHP",
				"MySQL",
				"jQuery"
			],
			"html": [
				"<!--\\s+#+ powered by the photoshelter beam platform",
				"<link[^>]+c\\.photoshelter\\.com"
			]
		},
		"Select2": {
			"implies": [
				"jQuery"
			],
			"js": [
				"jquery.fn.select2"
			]
		},
		"actionhero.js": {
			"headers": {
				"x-powered-by": "actionhero api"
			},
			"js": [
				"actionheroclient"
			],
			"implies": [
				"Node.js"
			]
		},
		"Platform.sh": {
			"headers": {
				"x-platform-cluster": ""
			}
		},
		"Raychat": {
			"js": [
				"raychat"
			]
		},
		"MyBB": {
			"implies": [
				"PHP",
				"MySQL"
			],
			"js": [
				"mybb"
			],
			"html": [
				"(?:<script [^>]+\\s+<!--\\s+lang\\.no_new_posts|<a[^>]* title=\"powered by mybb)"
			]
		},
		"CubeCart": {
			"meta": {
				"generator": [
					"cubecart"
				]
			},
			"html": [
				"(?:powered by <a href=[^>]+cubecart\\.com|<p[^>]+>powered by cubecart)"
			],
			"implies": [
				"PHP"
			]
		},
		"amoCRM": {
			"js": [
				"amoformswidget",
				"amosocialbutton",
				"amocrm",
				"amo_pixel_client"
			]
		},
		"JET Enterprise": {
			"headers": {
				"powered": "jet-enterprise"
			}
		},
		"Leanplum": {
			"js": [
				"leanplum"
			]
		},
		"Prism": {
			"js": [
				"prism"
			]
		},
		"vBulletin": {
			"cookies": {
				"bblastactivity": ""
			},
			"meta": {
				"generator": [
					"vbulletin ?([\\d.]+)?"
				]
			},
			"js": [
				"vbulletin"
			],
			"implies": [
				"PHP"
			],
			"html": [
				"<div id=\"copyright\">powered by vbulletin"
			]
		},
		"WebsPlanet": {
			"meta": {
				"generator": [
					"websplanet"
				]
			}
		},
		"Adobe Experience Platform Identity Service": {
			"js": [
				"s_c_il.0._c",
				"s_c_il.1._c",
				"s_c_il.2._c",
				"s_c_il.3._c",
				"s_c_il.4._c",
				"s_c_il.5._c"
			]
		},
		"Weglot": {
			"headers": {
				"weglot-translated": ""
			}
		},
		"Apache": {
			"headers": {
				"server": "(?:apache(?:$|\/([\\d.]+)|[^\/-])|(?:^|\\b)httpd)"
			}
		},
		"Indico": {
			"cookies": {
				"makacsession": ""
			},
			"html": [
				"powered by\\s+(?:cern )?<a href=\"http:\/\/(?:cdsware\\.cern\\.ch\/indico\/|indico-software\\.org|cern\\.ch\/indico)\">(?:cds )?indico( [\\d\\.]+)?"
			]
		},
		"GitLab": {
			"cookies": {
				"_gitlab_session": ""
			},
			"meta": {
				"og:site_name": [
					"^gitlab$"
				]
			},
			"js": [
				"gitlab",
				"gl.dashboardoptions"
			],
			"implies": [
				"Ruby on Rails",
				"Vue.js"
			],
			"html": [
				"<meta content=\"https?:\/\/[^\/]+\/assets\/gitlab_logo-",
				"<header class=\"navbar navbar-fixed-top navbar-gitlab with-horizontal-nav\">"
			]
		},
		"Craft CMS": {
			"cookies": {
				"craftsessionid": ""
			},
			"headers": {
				"x-powered-by": "\\bcraft cms\\b"
			},
			"implies": [
				"Yii"
			]
		},
		"Onshop": {
			"meta": {
				"generator": [
					"onshop ecommerce"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"SoftTr": {
			"meta": {
				"author": [
					"softtr e-ticaret sitesi yazılımı"
				]
			}
		},
		"UserVoice": {
			"js": [
				"uservoice"
			]
		},
		"Website Creator": {
			"meta": {
				"wsc_rendermode": [

				],
				"generator": [
					"website creator by hosttech"
				]
			},
			"implies": [
				"PHP",
				"MySQL",
				"Vue.js"
			]
		},
		"Klarna Checkout": {
			"js": [
				"_klarnacheckout"
			]
		},
		"Yahoo! Web Analytics": {
			"js": [
				"ywa"
			]
		},
		"Vimeo": {
			"js": [
				"vimeo.player",
				"vimeoplayer"
			],
			"html": [
				"(?:<(?:param|embed)[^>]+vimeo\\.com\/moogaloop|<iframe[^>]player\\.vimeo\\.com)"
			]
		},
		"DokuWiki": {
			"cookies": {
				"dokuwiki": ""
			},
			"meta": {
				"generator": [
					"^dokuwiki( release [\\d-]+)?"
				]
			},
			"implies": [
				"PHP"
			],
			"html": [
				"<div[^>]+id=\"dokuwiki__>",
				"<a[^>]+href=\"#dokuwiki__"
			]
		},
		"Microsoft ASP.NET": {
			"cookies": {
				"asp.net_sessionid": ""
			},
			"headers": {
				"x-powered-by": "^asp\\.net",
				"x-aspnet-version": "(.+)"
			},
			"implies": [
				"IIS"
			],
			"html": [
				"<input[^>]+name=\"__viewstate"
			]
		},
		"libwww-perl-daemon": {
			"headers": {
				"server": "libwww-perl-daemon(?:\/([\\d\\.]+))?"
			},
			"implies": [
				"Perl"
			]
		},
		"Ochanoko": {
			"js": [
				"ocnkproducts"
			]
		},
		"Adobe ColdFusion": {
			"js": [
				"_cfemails"
			],
			"headers": {
				"cookie": "cftoken="
			},
			"html": [
				"<!-- start headertags\\.cfm"
			],
			"implies": [
				"CFML"
			]
		},
		"GrowingIO": {
			"cookies": {
				"gr_user_id": ""
			}
		},
		"SpinCMS": {
			"cookies": {
				"spincms_session": ""
			},
			"implies": [
				"PHP"
			]
		},
		"Indy": {
			"headers": {
				"server": "indy(?:\/([\\d.]+))?"
			}
		},
		"Swiper Slider": {
			"js": [
				"swiper"
			],
			"html": [
				"<[^>]+=swiper-container"
			]
		},
		"Clickbank": {
			"js": [
				"cbtb"
			]
		},
		"Proximis Unified Commerce": {
			"meta": {
				"generator": [
					"proximis unified commerce"
				]
			},
			"js": [
				"__change"
			],
			"implies": [
				"PHP",
				"AngularJS"
			],
			"html": [
				"<html[^>]+data-ng-app=\"rbschangeapp\""
			]
		},
		"Twitter Ads": {
			"js": [
				"twttr"
			]
		},
		"Spinnakr": {
			"js": [
				"_spinnakr_site_id"
			]
		},
		"RiteCMS": {
			"meta": {
				"generator": [
					"^ritecms(?: (.+))?"
				]
			},
			"implies": [
				"PHP",
				"SQLite"
			]
		},
		"Red Hat": {
			"headers": {
				"server": "red hat",
				"x-powered-by": "red hat"
			}
		},
		"Dokeos": {
			"meta": {
				"generator": [
					"dokeos"
				]
			},
			"headers": {
				"x-powered-by": "dokeos"
			},
			"implies": [
				"PHP",
				"Xajax",
				"jQuery",
				"CKEditor"
			],
			"html": [
				"(?:portal <a[^>]+>dokeos|@import \"[^\"]+dokeos_blue)"
			]
		},
		"Captch Me": {
			"js": [
				"captchme"
			]
		},
		"ImpressCMS": {
			"cookies": {
				"icmssession": ""
			},
			"meta": {
				"generator": [
					"impresscms"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"Amazon ALB": {
			"cookies": {
				"awsalb": ""
			},
			"implies": [
				"Amazon Web Services"
			]
		},
		"Aurelia": {
			"html": [
				"<[^>]+aurelia-app=[^>]",
				"<[^>]+data-main=[^>]aurelia-bootstrapper",
				"<[^>]+au-target-id=[^>]\\d"
			]
		},
		"Zone.js": {
			"implies": [
				"Angular"
			],
			"js": [
				"zone.root"
			]
		},
		"mod_rack": {
			"headers": {
				"x-powered-by": "mod_rack(?:\/([\\d.]+))?",
				"server": "mod_rack(?:\/([\\d.]+))?"
			},
			"implies": [
				"Ruby on Rails",
				"Apache"
			]
		},
		"Gentoo": {
			"headers": {
				"x-powered-by": "gentoo"
			}
		},
		"Pagevamp": {
			"headers": {
				"x-servedby": "pagevamp"
			},
			"js": [
				"pagevamp"
			]
		},
		"Sucuri": {
			"headers": {
				"x-sucuri-cache:": ""
			}
		},
		"SonarQube": {
			"meta": {
				"application-name": [
					"^sonarqubes$"
				]
			},
			"js": [
				"sonarmeasures",
				"sonarrequest"
			],
			"implies": [
				"Java"
			],
			"html": [
				"<link href=\"\/css\/sonar\\.css\\?v=([\\d.]+)",
				"<title>sonarqube<\/title>"
			]
		},
		"Akaunting": {
			"headers": {
				"x-akaunting": "^free accounting software$"
			},
			"html": [
				"<link[^>]+akaunting-green\\.css",
				"powered by akaunting: <a [^>]*href=\"https?:\/\/(?:www\\.)?akaunting\\.com[^>]+>"
			],
			"implies": [
				"Laravel"
			]
		},
		"Mono": {
			"headers": {
				"x-powered-by": "mono"
			}
		},
		"Caddy": {
			"headers": {
				"server": "^caddy$"
			},
			"implies": [
				"Go"
			]
		},
		"ClearSale": {
			"js": [
				"window.csdm"
			]
		},
		"FreeBSD": {
			"headers": {
				"server": "freebsd(?: ([\\d.]+))?"
			}
		},
		"CleverTap": {
			"js": [
				"clevertap"
			]
		},
		"Dynamicweb": {
			"cookies": {
				"dynamicweb": ""
			},
			"meta": {
				"generator": [
					"dynamicweb ([\\d.]+)"
				]
			},
			"implies": [
				"Microsoft ASP.NET"
			]
		},
		"Smartsupp": {
			"js": [
				"$smartsupp.options.widgetversion",
				"smartsupp"
			]
		},
		"GSAP": {
			"js": [
				"tweenmax",
				"gsapversions"
			]
		},
		"Arastta": {
			"headers": {
				"arastta": "^(.+)$",
				"x-arastta": ""
			},
			"html": [
				"powered by <a [^>]*href=\"https?:\/\/(?:www\\.)?arastta\\.org[^>]+>arastta"
			],
			"implies": [
				"PHP"
			]
		},
		"Combeenation": {
			"html": [
				"<iframe[^>]+src=\"[^>]+portal\\.combeenation\\.com"
			]
		},
		"Sitevision CMS": {
			"cookies": {
				"sitevisionltm": ""
			}
		},
		"mod_dav": {
			"headers": {
				"server": "\\b(?:mod_)?dav\\b(?:\/([\\d.]+))?"
			},
			"implies": [
				"Apache"
			]
		},
		"KeyCDN": {
			"headers": {
				"server": "^keycdn-engine$"
			}
		},
		"Instabot": {
			"js": [
				"instabot"
			]
		},
		"SMF": {
			"implies": [
				"PHP"
			],
			"js": [
				"smf_"
			],
			"html": [
				"credits\/?\" title=\"simple machines forum\" target=\"_blank\" class=\"new_win\">smf ([0-9.]+)<\/a>"
			]
		},
		"Pygments": {
			"html": [
				"<link[^>]+pygments\\.css[\"']"
			]
		},
		"HubSpot CMS Hub": {
			"headers": {
				"x-hs-hub-id": ""
			},
			"meta": {
				"generator": [
					"hubspot"
				]
			},
			"implies": [
				"HubSpot"
			]
		},
		"pinoox": {
			"cookies": {
				"pinoox_session": ""
			},
			"js": [
				"pinoox"
			],
			"implies": [
				"PHP"
			]
		},
		"MediaElement.js": {
			"js": [
				"mejs",
				"mejs.version"
			]
		},
		"enduro.js": {
			"headers": {
				"x-powered-by": "^enduro\\.js"
			},
			"implies": [
				"Node.js"
			]
		},
		"Pantheon": {
			"headers": {
				"x-pantheon-styx-hostname": ""
			},
			"implies": [
				"PHP",
				"Nginx",
				"MariaDB",
				"Fastly"
			]
		},
		"Popper": {
			"js": [
				"createpopper"
			],
			"html": [
				"<script [^>]*src=\"[^\"]*\/popper\\.js\/([0-9.]+)"
			]
		},
		"Taggbox": {
			"js": [
				"taggboxajaxurl"
			]
		},
		"CodeIgniter": {
			"cookies": {
				"ci_session": "",
				"ci_csrf_token": "^(.+)$"
			},
			"html": [
				"<input[^>]+name=\"ci_csrf_token\""
			],
			"implies": [
				"PHP"
			]
		},
		"Wistia": {
			"js": [
				"wistia",
				"wistiaembeds",
				"wistiautils"
			]
		},
		"Frosmo": {
			"js": [
				"_frosmo",
				"frosmo"
			]
		},
		"Salesforce Commerce Cloud": {
			"js": [
				"dwanalytics"
			],
			"headers": {
				"server": "demandware ecommerce server"
			},
			"html": [
				"<[^>]+demandware\\.edgesuite"
			],
			"implies": [
				"Salesforce"
			]
		},
		"PersonaClick": {
			"js": [
				"personaclick",
				"personaclick_callback"
			]
		},
		"Docusaurus": {
			"meta": {
				"generator": [
					"^docusaurus(?: v(.+))?$"
				]
			},
			"js": [
				"search.indexname"
			],
			"implies": [
				"React",
				"webpack"
			]
		},
		"TYPO3 CMS": {
			"meta": {
				"generator": [
					"typo3\\s+(?:cms\\s+)?(?:[\\d.]+)?(?:\\s+cms)?"
				]
			},
			"html": [
				"<link[^>]+ href=\"\/?typo3(?:conf|temp)\/",
				"<img[^>]+ src=\"\/?typo3(?:conf|temp)\/",
				"<!--\n\tthis website is powered by typo3"
			],
			"implies": [
				"PHP"
			]
		},
		"IIS": {
			"headers": {
				"server": "^(?:microsoft-)?iis(?:\/([\\d.]+))?"
			},
			"implies": [
				"Windows Server"
			]
		},
		"AppNexus": {
			"js": [
				"appnexus",
				"appnexusvideo"
			]
		},
		"deepMiner": {
			"js": [
				"deepminer"
			]
		},
		"Blessing Skin": {
			"implies": [
				"Laravel"
			],
			"js": [
				"blessing.version"
			]
		},
		"FluxBB": {
			"implies": [
				"PHP"
			],
			"html": [
				"<p id=\"poweredby\">[^<]+<a href=\"https?:\/\/fluxbb\\.org\/\">"
			]
		},
		"Mouse Flow": {
			"js": [
				"_mfq"
			]
		},
		"DreamWeaver": {
			"js": [
				"mm_showhidelayers",
				"mm_showmenu",
				"mm_preloadimages"
			],
			"html": [
				"<!--[^>]*(?:instancebegineditable|dreamweaver([^>]+)target|dwlayoutdefaulttable)"
			]
		},
		"RequireJS": {
			"js": [
				"requirejs.version"
			]
		},
		"MathJax": {
			"js": [
				"mathjax",
				"mathjax.version"
			]
		},
		"Sazito": {
			"meta": {
				"generator": [
					"^sazito"
				]
			},
			"js": [
				"sazito"
			]
		},
		"ef.js": {
			"js": [
				"ef.version",
				"efcore"
			]
		},
		"RockRMS": {
			"meta": {
				"generator": [
					"^rock v([0-9.]+)"
				]
			},
			"implies": [
				"Windows Server",
				"IIS",
				"Microsoft ASP.NET"
			]
		},
		"Apple Sign-in": {
			"js": [
				"appleid"
			],
			"html": [
				"<meta[ˆ>]*appleid-signin-client-id"
			]
		},
		"Moment.js": {
			"js": [
				"moment.version",
				"moment"
			]
		},
		"Nuvemshop": {
			"html": [
				"<a target=\"_blank\" title=\"nuvemshop\""
			]
		},
		"Amber": {
			"headers": {
				"x-powered-by": "^amber$"
			}
		},
		"Raptor": {
			"js": [
				"raptor",
				"onraptorloaded",
				"raptorbase64"
			]
		},
		"Blade": {
			"headers": {
				"x-powered-by": "blade-([\\w.]+)?"
			},
			"implies": [
				"Java"
			]
		},
		"Linkedin Sign-in": {
			"js": [
				"onlinkedinauth",
				"onlinkedinload"
			]
		},
		"FlexCMP": {
			"headers": {
				"x-flex-lang": ""
			},
			"html": [
				"<!--[^>]+flexcmp[^>v]+v\\. ([\\d.]+)"
			],
			"meta": {
				"generator": [
					"^flexcmp"
				]
			}
		},
		"Cross Pixel": {
			"js": [
				"cp_c4w1ldn2d9pmvrkn"
			]
		},
		"Sizmek": {
			"html": [
				"(?:<a [^>]*href=\"[^\/]*\/\/[^\/]*serving-sys\\.com\/|<img [^>]*src=\"[^\/]*\/\/[^\/]*serving-sys\\.com\/)"
			]
		},
		"OpenCms": {
			"headers": {
				"server": "opencms"
			},
			"html": [
				"<link href=\"\/opencms\/"
			],
			"implies": [
				"Java"
			]
		},
		"jQuery-pjax": {
			"meta": {
				"pjax-replace": [

				],
				"pjax-timeout": [

				],
				"pjax-push": [

				]
			},
			"js": [
				"jquery.pjax"
			],
			"implies": [
				"jQuery"
			],
			"html": [
				"<div[^>]+data-pjax-container"
			]
		},
		"Flyspray": {
			"cookies": {
				"flyspray_project": ""
			},
			"html": [
				"(?:<a[^>]+>powered by flyspray|<map id=\"projectsearchform)"
			],
			"implies": [
				"PHP"
			]
		},
		"Launchrock": {
			"js": [
				"lrsitesettingasboolean",
				"lrignition",
				"lrignition",
				"lrloadedjs"
			]
		},
		"Dotdigital": {
			"js": [
				"dm_insight_id",
				"dmtrackingobjectname",
				"dmpt"
			]
		},
		"Next.js": {
			"headers": {
				"x-powered-by": "^next\\.js ?([0-9.]+)?"
			},
			"js": [
				"__next_data__"
			],
			"implies": [
				"React",
				"webpack",
				"Node.js"
			]
		},
		"Afosto": {
			"headers": {
				"x-powered-by": "afosto saas bv"
			}
		},
		"Plesk": {
			"headers": {
				"x-powered-by": "^plesk(?:l|w)in",
				"x-powered-by-plesk": "^plesk"
			}
		},
		"Fbits": {
			"js": [
				"fbits"
			]
		},
		"HHVM": {
			"headers": {
				"x-powered-by": "hhvm\/?([\\d.]+)?"
			},
			"implies": [
				"PHP"
			]
		},
		"Essential JS 2": {
			"html": [
				"<[^>]+ class ?= ?\"(?:e-control|[^\"]+ e-control)(?: )[^\"]* e-lib\\b"
			]
		},
		"tailwindcss": {
			"html": [
				"<link[^>]+?href=\"[^\"]+tailwindcss[@|\/](?:\\^)?([\\d.]+)(?:\/[a-z]+)?\/(?:tailwind|base|components|utilities)(?:\\.min)?\\.css"
			]
		},
		"uPortal": {
			"meta": {
				"description": [
					" uportal "
				]
			},
			"js": [
				"uportal"
			],
			"implies": [
				"Java"
			]
		},
		"MemberStack": {
			"cookies": {
				"memberstack": ""
			},
			"js": [
				"memberstack"
			]
		},
		"Analysys Ark": {
			"cookies": {
				"ark_id": ""
			},
			"js": [
				"analysysagent"
			]
		},
		"eZ Platform": {
			"meta": {
				"generator": [
					"ez platform"
				]
			},
			"implies": [
				"Symfony"
			]
		},
		"CoverManager": {
			"html": [
				"<iframe[^>]*covermanager\\.com\/reservation"
			]
		},
		"Flarum": {
			"implies": [
				"PHP",
				"MySQL"
			],
			"js": [
				"app.cache.discussionlist",
				"app.forum.freshness"
			],
			"html": [
				"<div id=\"flarum-loading\""
			]
		},
		"webpack": {
			"js": [
				"webpackjsonp"
			]
		},
		"Luigi’s Box": {
			"js": [
				"luigis"
			]
		},
		"Bloomreach": {
			"html": [
				"<[^>]+\/binaries\/(?:[^\/]+\/)*content\/gallery\/"
			]
		},
		"wisyCMS": {
			"meta": {
				"generator": [
					"^wisy cms[ v]{0,3}([0-9.,]*)"
				]
			}
		},
		"Mixpanel": {
			"js": [
				"mixpanel"
			]
		},
		"Microsoft Word": {
			"meta": {
				"generator": [
					"microsoft word( [\\d.]+)?"
				],
				"progid": [
					"^word\\."
				]
			},
			"html": [
				"(?:<html [^>]*xmlns:w=\"urn:schemas-microsoft-com:office:word\"|<w:worddocument>|<div [^>]*class=\"?wordsection1[\" >]|<style[^>]*>[^>]*@page wordsection1)"
			]
		},
		"Taiga": {
			"implies": [
				"Django",
				"AngularJS"
			],
			"js": [
				"taigaconfig"
			]
		},
		"MoEngage": {
			"js": [
				"moengage_api_key",
				"moengage",
				"downloadmoengage",
				"moengage_object"
			]
		},
		"Froala Editor": {
			"implies": [
				"jQuery",
				"Font Awesome"
			],
			"html": [
				"<[^>]+class=\"[^\"]*(?:fr-view|fr-box)"
			]
		},
		"Microsoft Advertising": {
			"cookies": {
				"_uetsid": "\\w+",
				"_uetvid": "\\w+"
			},
			"js": [
				"uet",
				"uetq"
			]
		},
		"Java": {
			"cookies": {
				"jsessionid": ""
			}
		},
		"Raphael": {
			"js": [
				"raphael.version"
			]
		},
		"Tealium": {
			"js": [
				"tealiumenabled"
			]
		},
		"Azion": {
			"headers": {
				"server": "^azion "
			}
		},
		"phpwind": {
			"meta": {
				"generator": [
					"^phpwind(?: v([0-9-]+))?"
				]
			},
			"html": [
				"(?:powered|code) by <a href=\"[^\"]+phpwind\\.net"
			],
			"implies": [
				"PHP"
			]
		},
		"Fedora": {
			"headers": {
				"server": "fedora"
			}
		},
		"Hello Bar": {
			"js": [
				"hellobar"
			]
		},
		"Oracle Application Server": {
			"headers": {
				"server": "oracle[- ]application[- ]server(?: containers for j2ee)?(?:[- ](\\d[\\da-z.\/]+))?"
			}
		},
		"webEdition": {
			"meta": {
				"dc.title": [
					"webedition"
				],
				"generator": [
					"webedition"
				]
			}
		},
		"YUI": {
			"js": [
				"yahoo.version",
				"yui.version"
			]
		},
		"Cufon": {
			"js": [
				"cufon"
			]
		},
		"Apollo": {
			"implies": [
				"GraphQL",
				"TypeScript"
			],
			"js": [
				"__apollo_client__",
				"__apollo_client__.version"
			]
		},
		"AD EBiS": {
			"html": [
				"<!-- ebis contents tag",
				"<!--ebis tag",
				"<!-- tag ebis",
				"<!-- ebis common tag"
			]
		},
		"Mapbox GL JS": {
			"js": [
				"mapboxgl.version"
			]
		},
		"RDoc": {
			"implies": [
				"Ruby"
			],
			"js": [
				"rdoc_rel_prefix"
			],
			"html": [
				"<link[^>]+href=\"[^\"]*rdoc-style\\.css",
				"generated by <a[^>]+href=\"https?:\/\/rdoc\\.rubyforge\\.org[^>]+>rdoc<\/a> ([\\d.]*\\d)",
				"generated by <a href=\"https:\\\/\\\/ruby\\.github\\.io\\\/rdoc\\\/\">rdoc<\\\/a> ([\\d.]*\\d)"
			]
		},
		"RoundCube": {
			"implies": [
				"PHP"
			],
			"js": [
				"rcmail",
				"roundcube"
			],
			"html": [
				"<title>roundcube"
			]
		},
		"Acquia Cloud Platform": {
			"headers": {
				"x-ah-environment": "^\\w+$"
			},
			"implies": [
				"Drupal",
				"Apache",
				"Percona",
				"Amazon EC2"
			]
		},
		"Squiz Matrix": {
			"meta": {
				"generator": [
					"squiz matrix"
				]
			},
			"headers": {
				"x-powered-by": "squiz matrix"
			},
			"implies": [
				"PHP"
			],
			"html": [
				"<!--\\s+running (?:mysource|squiz) matrix"
			]
		},
		"Uscreen": {
			"js": [
				"analyticshost"
			]
		},
		"Mura CMS": {
			"meta": {
				"generator": [
					"mura cms ([\\d]+)"
				]
			},
			"implies": [
				"Adobe ColdFusion"
			]
		},
		"swift.engine": {
			"headers": {
				"x-powered-by": "swift\\.engine"
			}
		},
		"TinyMCE": {
			"js": [
				"tinymce.majorversion"
			]
		},
		"Prototype": {
			"js": [
				"prototype.version"
			]
		},
		"particles.js": {
			"js": [
				"particlesjs"
			],
			"html": [
				"<div id=\"particles-js\">"
			]
		},
		"Elcodi": {
			"headers": {
				"x-elcodi": ""
			},
			"implies": [
				"PHP",
				"Symfony"
			]
		},
		"Simbel": {
			"headers": {
				"powered": "simbel"
			}
		},
		"OpenText Web Solutions": {
			"implies": [
				"Microsoft ASP.NET"
			],
			"html": [
				"<!--[^>]+published by open text web solutions"
			]
		},
		"Jumpseller": {
			"js": [
				"jumpseller"
			]
		},
		"Snipcart": {
			"cookies": {
				"snipcart-cart": ""
			}
		},
		"Chart.js": {
			"js": [
				"chart",
				"chart.defaults.doughnut",
				"chart.ctx.beziercurveto"
			]
		},
		"Mercado Shops": {
			"cookies": {
				"_mshops_ga_gid": ""
			}
		},
		"Twitter typeahead.js": {
			"implies": [
				"jQuery"
			],
			"js": [
				"typeahead"
			]
		},
		"Liferay": {
			"headers": {
				"liferay-portal": "[a-z\\s]+([\\d.]+)"
			},
			"js": [
				"liferay"
			]
		},
		"Signal": {
			"js": [
				"signaldata"
			]
		},
		"4-Tell": {
			"cookies": {
				"4tell": ""
			},
			"js": [
				"_4tellboost"
			]
		},
		"Timeplot": {
			"js": [
				"timeplot"
			]
		},
		"Debian": {
			"headers": {
				"x-powered-by": "(?:debian|dotdeb|(potato|woody|sarge|etch|lenny|squeeze|wheezy|jessie|stretch|buster|sid))",
				"server": "debian"
			}
		},
		"Visualsoft": {
			"cookies": {
				"vscommerce": ""
			},
			"meta": {
				"vsvatprices": [

				],
				"vs_status_checker_version": [
					"\\d+"
				]
			}
		},
		"Microsoft HTTPAPI": {
			"headers": {
				"server": "microsoft-httpapi(?:\/([\\d.]+))?"
			}
		},
		"Pligg": {
			"meta": {
				"generator": [
					"pligg"
				]
			},
			"js": [
				"pligg_"
			],
			"html": [
				"<span[^>]+id=\"xvotes-0"
			]
		},
		"Apigee": {
			"html": [
				"<script>[^>]{0,50}script src=[^>]\/profiles\/apigee"
			]
		},
		"Zimbra": {
			"cookies": {
				"zm_test": "true"
			},
			"implies": [
				"Java"
			]
		},
		"Amazon ELB": {
			"cookies": {
				"awselb": ""
			},
			"implies": [
				"Amazon Web Services"
			]
		},
		"Sails.js": {
			"cookies": {
				"sails.sid": ""
			},
			"headers": {
				"x-powered-by": "^sails(?:$|[^a-z0-9])"
			},
			"implies": [
				"Express"
			]
		},
		"Bulma": {
			"html": [
				"<link[^>]+?href=\"[^\"]+bulma(?:\\.min)?\\.css"
			]
		},
		"Symfony": {
			"cookies": {
				"sf_redirect": ""
			},
			"js": [
				"sfjs"
			],
			"implies": [
				"PHP"
			],
			"html": [
				"<div id=\"sfwdt[^\"]+\" class=\"[^\"]*sf-toolbar"
			]
		},
		"Halo": {
			"meta": {
				"generator": [
					"halo ([\\d.]+)?"
				]
			},
			"implies": [
				"Java"
			]
		},
		"Commerce Server": {
			"headers": {
				"commerce-server-software": ""
			},
			"implies": [
				"Microsoft ASP.NET"
			]
		},
		"Brightspot": {
			"headers": {
				"x-powered-by": "^brightspot$"
			},
			"implies": [
				"Java"
			]
		},
		"TeamCity": {
			"meta": {
				"application-name": [
					"teamcity"
				]
			},
			"html": [
				"<span class=\"versiontag\"><span class=\"vword\">version<\/span> ([\\d\\.]+)"
			],
			"implies": [
				"Apache Tomcat",
				"Java",
				"jQuery",
				"Moment.js",
				"Prototype",
				"React",
				"Underscore.js"
			]
		},
		"Material Design Lite": {
			"js": [
				"materialicontoggle"
			],
			"html": [
				"<link[^>]* href=\"[^\"]*material(?:\\.[\\w]+-[\\w]+)?(?:\\.min)?\\.css"
			]
		},
		"Parse.ly": {
			"js": [
				"parsely"
			]
		},
		"Jekyll": {
			"meta": {
				"generator": [
					"jekyll (v[\\d.]+)?"
				]
			},
			"html": [
				"powered by <a href=\"https?:\/\/jekyllrb\\.com\"[^>]*>jekyll<\/",
				"<!-- created with jekyll now -",
				"<!-- begin jekyll seo tag"
			]
		},
		"ThinkPHP": {
			"headers": {
				"x-powered-by": "thinkphp"
			},
			"implies": [
				"PHP"
			]
		},
		"Tictail": {
			"html": [
				"<link[^>]*tictail\\.com"
			]
		},
		"Flickity": {
			"js": [
				"flickity"
			]
		},
		"Shopcada": {
			"js": [
				"shopcada"
			]
		},
		"Braze": {
			"js": [
				"appboy",
				"appboyqueue"
			]
		},
		"ExpressionEngine": {
			"cookies": {
				"exp_csrf_token": ""
			},
			"implies": [
				"PHP"
			]
		},
		"Darwin": {
			"headers": {
				"server": "darwin",
				"x-powered-by": "darwin"
			}
		},
		"Resmio": {
			"js": [
				"resmiobutton"
			]
		},
		"LiveStreet CMS": {
			"headers": {
				"x-powered-by": "livestreet cms"
			},
			"js": [
				"livestreet_security_key"
			],
			"implies": [
				"PHP"
			]
		},
		"AlertifyJS": {
			"js": [
				"alertify.defaults.autoreset"
			]
		},
		"Adobe Experience Manager": {
			"implies": [
				"Java"
			],
			"html": [
				"<div class=\"[^\"]*parbase",
				"<div[^>]+data-component-path=\"[^\"+]jcr:",
				"<div class=\"[^\"]*aem-grid"
			]
		},
		"Koha": {
			"meta": {
				"generator": [
					"^koha ([\\d.]+)$"
				]
			},
			"js": [
				"koha"
			],
			"implies": [
				"Perl"
			],
			"html": [
				"<input name=\"koha_login_context\" value=\"intranet\" type=\"hidden\">",
				"<a href=\"\/cgi-bin\/koha\/"
			]
		},
		"NodeBB": {
			"headers": {
				"x-powered-by": "^nodebb$"
			},
			"implies": [
				"Node.js"
			]
		},
		"Erlang": {
			"headers": {
				"server": "erlang( otp\/(?:[\\d.abr-]+))?"
			}
		},
		"Google Code Prettify": {
			"js": [
				"prettyprint"
			]
		},
		"Square": {
			"js": [
				"sqpaymentform",
				"square.analytics"
			]
		},
		"CoinHive": {
			"js": [
				"coinhive"
			]
		},
		"Searchspring": {
			"js": [
				"searchspring",
				"searchspringconf",
				"searchspringinit"
			]
		},
		"Setmore": {
			"js": [
				"setmorepopup"
			]
		},
		"Retail Rocket": {
			"cookies": {
				"rr-testcookie": "testvalue",
				"rrpvid": "^\\d+$"
			},
			"js": [
				"retailrocket",
				"rraddtobasket",
				"rrapionready",
				"rrlibrary",
				"rrpartnerid"
			]
		},
		"TrackJs": {
			"js": [
				"trackjs"
			]
		},
		"Blue": {
			"js": [
				"blueproductid",
				"bluecpy_id"
			]
		},
		"OpenLayers": {
			"js": [
				"openlayers.version_number",
				"ol.canvasmap"
			]
		},
		"IBM DataPower": {
			"headers": {
				"x-backside-transport": ""
			}
		},
		"phpSQLiteCMS": {
			"meta": {
				"generator": [
					"^phpsqlitecms(?: (.+))?$"
				]
			},
			"implies": [
				"PHP",
				"SQLite"
			]
		},
		"Elementor": {
			"js": [
				"elementorfrontend.getelements"
			],
			"html": [
				"<div class=(?:\"|')[^\"']*elementor",
				"<section class=(?:\"|')[^\"']*elementor",
				"<link [^>]*href=(?:\"|')[^\"']*elementor\/assets",
				"<link [^>]*href=(?:\"|')[^\"']*uploads\/elementor\/css"
			]
		},
		"Trbo": {
			"cookies": {
				"trbo_session": "^(?:[\\d]+)$",
				"trbo_usr": "^(?:[\\d\\w]+)$"
			},
			"js": [
				"_trboq",
				"_trbo",
				"_trbo_start"
			]
		},
		"JAlbum": {
			"meta": {
				"generator": [
					"jalbum( [\\d.]+)?"
				]
			},
			"implies": [
				"Java"
			]
		},
		"ownCloud": {
			"meta": {
				"apple-itunes-app": [
					"app-id=543672169"
				]
			},
			"html": [
				"<a href=\"https:\/\/owncloud\\.com\" target=\"_blank\">owncloud inc\\.<\/a><br\/>your cloud, your data, your way!"
			],
			"implies": [
				"PHP"
			]
		},
		"Underscore.js": {
			"js": [
				"_.version",
				"_.restarguments"
			]
		},
		"WebAssembly": {
			"headers": {
				"content-type": "application\/wasm"
			}
		},
		"Oribi": {
			"js": [
				"oribi"
			]
		},
		"JobberBase": {
			"meta": {
				"generator": [
					"jobberbase"
				]
			},
			"js": [
				"jobber"
			],
			"implies": [
				"PHP"
			]
		},
		"Eloqua": {
			"js": [
				"elqcuresite",
				"elqload",
				"elqsiteid",
				"elq_global"
			]
		},
		"PIXIjs": {
			"js": [
				"pixi",
				"pixi.version"
			]
		},
		"Sovrn": {
			"js": [
				"sovrn",
				"sovrn_render"
			]
		},
		"WebAR": {
			"html": [
				"<model-viewer"
			]
		},
		"Sapper": {
			"implies": [
				"Svelte",
				"Node.js"
			],
			"js": [
				"__sapper__"
			],
			"html": [
				"<script[^>]*>__sapper__"
			]
		},
		"TwistedWeb": {
			"headers": {
				"server": "twistedweb(?:\/([\\d.]+))?"
			}
		},
		"Hexo": {
			"meta": {
				"generator": [
					"hexo(?: v?([\\d.]+))?"
				]
			},
			"html": [
				"powered by <a href=\"https?:\/\/hexo\\.io\/?\"[^>]*>hexo<\/"
			],
			"implies": [
				"Node.js"
			]
		},
		"ApexPages": {
			"headers": {
				"x-powered-by": "salesforce\\.com apexpages"
			},
			"implies": [
				"Salesforce"
			]
		},
		"Slick": {
			"implies": [
				"jQuery"
			],
			"html": [
				"<link [^>]+(?:\/([\\d.]+)\/)?slick-theme\\.css"
			]
		},
		"ikiwiki": {
			"html": [
				"<link rel=\"alternate\" type=\"application\/x-wiki\" title=\"edit this page\" href=\"[^\"]*\/ikiwiki\\.cgi",
				"<a href=\"\/(?:cgi-bin\/)?ikiwiki\\.cgi\\?do="
			]
		},
		"Rewardful": {
			"js": [
				"rewardful"
			]
		},
		"NEO - Omnichannel Commerce Platform": {
			"headers": {
				"powered": "jet-neo"
			}
		},
		"Quantcast Measure": {
			"js": [
				"quantserve"
			]
		},
		"Phenomic": {
			"implies": [
				"React"
			],
			"html": [
				"<[^>]+id=\"phenomic(?:root)?\""
			]
		},
		"comScore": {
			"js": [
				"comscore",
				"_comscore"
			],
			"html": [
				"<iframe[^>]* (?:id=\"comscore\"|scr=[^>]+comscore)|\\.scorecardresearch\\.com\/beacon\\.js|comscore\\.beacon"
			]
		},
		"jQuery Migrate": {
			"implies": [
				"jQuery"
			],
			"js": [
				"jquery.migrateversion",
				"jquery.migratewarnings",
				"jquerymigrate"
			]
		},
		"reCAPTCHA": {
			"js": [
				"recaptcha",
				"recaptcha"
			],
			"html": [
				"<div[^>]+id=\"recaptcha_image",
				"<link[^>]+recaptcha",
				"<div[^>]+class=\"g-recaptcha\""
			]
		},
		"EasyDigitalDownloads": {
			"meta": {
				"generator": [
					"^easy digital downloads v(.*)$"
				]
			}
		},
		"ApostropheCMS": {
			"implies": [
				"Node.js"
			],
			"html": [
				"<[^>]+data-apos-refreshable[^>]"
			]
		},
		"SAP": {
			"headers": {
				"server": "sap netweaver application server"
			}
		},
		"Fastly": {
			"headers": {
				"x-fastly-origin": ""
			}
		},
		"Blip.tv": {
			"html": [
				"<(?:param|embed|iframe)[^>]+blip\\.tv\/play"
			]
		},
		"Google Analytics": {
			"cookies": {
				"__utma": ""
			},
			"js": [
				"googleanalyticsobject",
				"gaglobal"
			],
			"html": [
				"<amp-analytics [^>]*type=[\"']googleanalytics[\"']"
			]
		},
		"SWFObject": {
			"js": [
				"swfobject"
			]
		},
		"hCaptcha": {
			"html": [
				"<style[^>]+[^<]+#cf-hcaptcha-container[^<]+<\/style>"
			]
		},
		"Shoporama": {
			"meta": {
				"generator": [
					"shoporama"
				]
			}
		},
		"Gitiles": {
			"implies": [
				"Java",
				"git"
			],
			"html": [
				"powered by <a href=\"https:\/\/gerrit\\.googlesource\\.com\/gitiles\/\">gitiles<"
			]
		},
		"Ckan": {
			"headers": {
				"link": "<http:\/\/ckan\\.org\/>; rel=shortlink",
				"access-control-allow-headers": "x-ckan-api-key"
			},
			"meta": {
				"generator": [
					"^ckan ?([0-9.]+)$"
				]
			},
			"implies": [
				"Python",
				"Solr",
				"Java",
				"PostgreSQL"
			]
		},
		"Apache Traffic Server": {
			"headers": {
				"server": "ats\/?([\\d.]+)?"
			}
		},
		"script.aculo.us": {
			"js": [
				"scriptaculous.version"
			]
		},
		"Airform": {
			"html": [
				"<form[^>]+?action=\"[^\"]*airform\\.io[^>]+?>"
			]
		},
		"Disqus": {
			"js": [
				"disqus_url",
				"disqus",
				"disqus_shortname"
			],
			"html": [
				"<div[^>]+id=\"disqus_thread\""
			]
		},
		"XRegExp": {
			"js": [
				"xregexp.version"
			]
		},
		"Appointy": {
			"html": [
				"<iframe[^>]+src=\"?https:\/\/[\\w\\d\\-]+\\.appointy\\.com"
			]
		},
		"OneTrust": {
			"cookies": {
				"optanonconsent": ""
			}
		},
		"UMI.CMS": {
			"headers": {
				"x-generated-by": "umi\\.cms"
			},
			"implies": [
				"PHP"
			]
		},
		"Duopana": {
			"html": [
				"(?:<!-- \/*beracode script)"
			]
		},
		"Vanilla": {
			"headers": {
				"x-powered-by": "vanilla"
			},
			"html": [
				"<body id=\"(?:discussionspage|vanilla)"
			],
			"implies": [
				"PHP"
			]
		},
		"Upvoty": {
			"implies": [
				"PHP"
			],
			"js": [
				"upvoty"
			]
		},
		"Maxemail": {
			"js": [
				"mxm.basket",
				"mxm.formhandler",
				"mxm.tracker"
			]
		},
		"ForoshGostar": {
			"cookies": {
				"aws.customer": ""
			},
			"meta": {
				"generator": [
					"^forosh\\s?gostar.*|arsina webshop.*$"
				]
			},
			"implies": [
				"Microsoft ASP.NET"
			]
		},
		"Aegea": {
			"headers": {
				"x-powered-by": "^e2 aegea v(\\d+)$"
			},
			"implies": [
				"PHP",
				"jQuery"
			]
		},
		"Oracle Web Cache": {
			"headers": {
				"server": "oracle(?:as)?[- ]web[- ]cache(?:[- \/]([\\da-z.\/]+))?"
			}
		},
		"Webtrekk": {
			"js": [
				"webtrekkunloadobjects",
				"webtrekkv3",
				"wt_tt",
				"webtrekkv3",
				"webtrekk",
				"webtrekklinktrackobjects",
				"webtrekkconfig",
				"webtrekkheatmapobjects",
				"wt_ttv2"
			]
		},
		"OpenSSL": {
			"headers": {
				"server": "openssl(?:\/([\\d.]+[a-z]?))?"
			}
		},
		"MobX": {
			"js": [
				"__mobxglobal",
				"__mobxglobals",
				"__mobxinstancecount"
			]
		},
		"Mautic": {
			"js": [
				"mautictrackingobject"
			]
		},
		"Allegro RomPager": {
			"headers": {
				"server": "allegro-software-rompager(?:\/([\\d.]+))?"
			}
		},
		"Chitika": {
			"js": [
				"ch_client",
				"ch_color_site_link"
			]
		},
		"Airee": {
			"headers": {
				"server": "^airee"
			}
		},
		"Wiki.js": {
			"implies": [
				"Node.js"
			],
			"js": [
				"wiki.$_apolloinitdata",
				"wiki.$apolloprovider"
			]
		},
		"Akamai": {
			"headers": {
				"x-akamai-transformed": ""
			}
		},
		"Highlight.js": {
			"js": [
				"hljs.highlightblock",
				"hljs.listlanguages"
			]
		},
		"Crisp Live Chat": {
			"js": [
				"$crisp",
				"crisp_website_id"
			]
		},
		"CMSimple": {
			"meta": {
				"generator": [
					"cmsimple( [\\d.]+)?"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"Slimbox 2": {
			"implies": [
				"jQuery"
			],
			"html": [
				"<link [^>]*href=\"[^\/]*slimbox2(?:-rtl)?\\.css"
			]
		},
		"Invenio": {
			"cookies": {
				"inveniosession": ""
			},
			"html": [
				"(?:powered by|system)\\s+(?:cern )?<a (?:class=\"footer\" )?href=\"http:\/\/(?:cdsware\\.cern\\.ch(?:\/invenio)?|invenio-software\\.org|cern\\.ch\/invenio)(?:\/)?\">(?:cds )?invenio<\/a>\\s*v?([\\d\\.]+)?"
			]
		},
		"Laterpay": {
			"meta": {
				"laterpay:connector:callbacks:on_user_has_access": [
					"deobfuscatetext"
				]
			}
		},
		"XAMPP": {
			"meta": {
				"author": [
					"kai oswald seidler"
				]
			},
			"html": [
				"<title>xampp(?: version ([\\d\\.]+))?<\/title>"
			],
			"implies": [
				"Apache",
				"MySQL",
				"PHP",
				"Perl"
			]
		},
		"Reveal.js": {
			"implies": [
				"Highlight.js"
			],
			"js": [
				"reveal.version"
			]
		},
		"Genesys Cloud": {
			"js": [
				"purecloud_webchat_frame_config"
			]
		},
		"Livefyre": {
			"js": [
				"fyreloader",
				"l.version",
				"lf.commentcount",
				"fyre"
			],
			"html": [
				"<[^>]+(?:id|class)=\"livefyre"
			]
		},
		"VerifyPass": {
			"js": [
				"verifypass_popup",
				"verifypass_api_instantiator",
				"verifypass_is_loaded"
			]
		},
		"mod_ssl": {
			"headers": {
				"server": "mod_ssl(?:\/([\\d.]+))?"
			},
			"implies": [
				"Apache"
			]
		},
		"Veoxa": {
			"js": [
				"vuveoxacontent"
			],
			"html": [
				"<img [^>]*src=\"[^\"]+tracking\\.veoxa\\.com"
			]
		},
		"SiteGround": {
			"headers": {
				"host-header": "192fc2e7e50945beb8231a492d6a8024|b7440e60b07ee7b8044761568fab26e8|624d5be7be38418a3e2a818cc8b7029b|6b7412fb82ca5edfd0917e3957f05d89"
			}
		},
		"Bookero": {
			"js": [
				"bookero_config"
			]
		},
		"WordPress": {
			"meta": {
				"generator": [
					"^wordpress ?([\\d.]+)?"
				],
				"shareaholic:wp_version": [

				]
			},
			"js": [
				"wp_username"
			],
			"headers": {
				"x-pingback": "\/xmlrpc\\.php$",
				"link": "rel=\"https:\/\/api\\.w\\.org\/\""
			},
			"html": [
				"wp-admin",
				"wp-content\/",
				"wp-",
				"wp-content\/themes\/",
				"<link rel=[\"']stylesheet[\"'] [^>]+\/wp-(?:content|includes)\/",
				"<link[^>]+s\\d+\\.wp\\.com"
			],
			"implies": [
				"PHP",
				"MySQL"
			]
		},
		"Grav": {
			"meta": {
				"generator": [
					"gravcms(?:\\s([\\d.]+))?"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"Medium": {
			"headers": {
				"x-powered-by": "^medium$"
			},
			"implies": [
				"Node.js"
			]
		},
		"Bluecore": {
			"js": [
				"bluecore_action_trigger",
				"triggermail",
				"triggermail_email_address",
				"_bluecoretrack"
			]
		},
		"Primis": {
			"js": [
				"sekindoflowingplayeron",
				"sekindonativeskinapi",
				"sekindodisplayedplacement"
			]
		},
		"Microsoft Clarity": {
			"js": [
				"clarity"
			]
		},
		"Google Analytics Enhanced eCommerce": {
			"implies": [
				"Google Analytics"
			],
			"js": [
				"gaplugins.ec"
			]
		},
		"WEBXPAY": {
			"js": [
				"webxpay"
			],
			"html": [
				"powered by <a href=\"https:\/\/www\\.webxpay\\.com\">webxpay<"
			]
		},
		"Adzerk": {
			"js": [
				"ados",
				"adosresults"
			],
			"html": [
				"<iframe [^>]*src=\"[^\"]+adzerk\\.net"
			]
		},
		"TypePad": {
			"meta": {
				"generator": [
					"typepad"
				]
			}
		},
		"Contentful": {
			"headers": {
				"x-contentful-request-id": ""
			},
			"html": [
				"<[^>]+(?:https?:)?\/\/(?:assets|downloads|images|videos)\\.(?:ct?fassets\\.net|contentful\\.com)"
			]
		},
		"Countly": {
			"js": [
				"countly"
			]
		},
		"BEM": {
			"html": [
				"<[^>]+data-bem"
			]
		},
		"Smartstore": {
			"cookies": {
				"smartstore.customer": ""
			},
			"meta": {
				"generator": [
					"^smart[ss]tore(.net)? (.+)$"
				]
			},
			"implies": [
				"Microsoft ASP.NET"
			],
			"html": [
				"<!--powered by smart[ss]tore",
				"<meta property=\"sm:pagedata\""
			]
		},
		"ImpressPages": {
			"meta": {
				"generator": [
					"impresspages(?: cms)?( [\\d.]*)?"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"SevenRooms": {
			"js": [
				"sevenroomswidget"
			]
		},
		"AWStats": {
			"meta": {
				"generator": [
					"awstats ([\\d.]+(?: \\(build [\\d.]+\\))?)"
				]
			},
			"implies": [
				"Perl"
			]
		},
		"Sentry": {
			"js": [
				"raven.config",
				"sentry",
				"sentry.sdk_version",
				"__sentry__",
				"ravenoptions.whitelisturls"
			],
			"html": [
				"<script[^>]*>\\s*raven\\.config\\('[^']*', \\{\\s+release: '([0-9\\.]+)'",
				"<script[^>]*src=\"[^\"]*browser\\.sentry\\-cdn\\.com\/([0-9.]+)\/bundle(?:\\.tracing)?(?:\\.min)?\\.js"
			]
		},
		"Hiawatha": {
			"headers": {
				"server": "hiawatha v([\\d.]+)"
			}
		},
		"Azure CDN": {
			"headers": {
				"x-ec-debug": ""
			}
		},
		"Intershop": {
			"html": [
				"<ish-root"
			]
		},
		"Chorus": {
			"html": [
				"<meta data-chorus-version="
			]
		},
		"LiveRamp PCM": {
			"js": [
				"wpjsonpliverampgdprcmp"
			]
		},
		"Discuz": {
			"meta": {
				"generator": [
					"discuz! x([\\d\\.]+)?"
				]
			},
			"js": [
				"discuzcode",
				"discuzversion",
				"discuz_uid"
			],
			"implies": [
				"PHP"
			]
		},
		"SilverStripe": {
			"meta": {
				"generator": [
					"^silverstripe"
				]
			},
			"html": [
				"powered by <a href=\"[^>]+silverstripe"
			],
			"implies": [
				"PHP"
			]
		},
		"Konduto": {
			"js": [
				"getkondutoid",
				"konduto"
			]
		},
		"Akamai Web Application Protector": {
			"implies": [
				"Akamai"
			],
			"js": [
				"aksb"
			]
		},
		"Socket.io": {
			"implies": [
				"Node.js"
			],
			"js": [
				"io.socket",
				"io.version"
			]
		},
		"Sky-Shop": {
			"meta": {
				"generator": [
					"sky-shop"
				]
			},
			"js": [
				"l.continue_shopping"
			],
			"implies": [
				"PHP",
				"Bootstrap",
				"jQuery"
			]
		},
		"Chaport": {
			"js": [
				"chaport",
				"chaportconfig"
			]
		},
		"Zen Cart": {
			"meta": {
				"generator": [
					"zen cart"
				]
			}
		},
		"OXID eShop Community Edition": {
			"implies": [
				"PHP"
			],
			"html": [
				"<!--[^-]*oxid eshop community edition, version (\\d+)"
			]
		},
		"American Express": {
			"html": [
				"<[^>]+aria-labelledby=\"pi-american_express"
			]
		},
		"Blueknow": {
			"js": [
				"blueknow",
				"blueknowtracker"
			]
		},
		"DatoCMS": {
			"html": [
				"<[^>]+https:\/\/www\\.datocms-assets\\.com"
			]
		},
		"Google AdSense": {
			"js": [
				"goog_adsense_",
				"goog_adsense_osdadapter",
				"__google_ad_urls",
				"google_ad_"
			]
		},
		"Apptus": {
			"cookies": {
				"apptus.customerkey": ""
			},
			"js": [
				"apptusesales",
				"apptusconfig",
				"apptusdebug"
			]
		},
		"ZURB Foundation": {
			"js": [
				"foundation.version"
			],
			"html": [
				"<link[^>]+foundation[^>\"]+css",
				"<div [^>]*class=\"[^\"]*(?:small|medium|large)-\\d{1,2} columns"
			]
		},
		"TwicPics": {
			"headers": {
				"server": "^twicpics\/\\d+\\.\\d+\\.\\d+$"
			}
		},
		"Bentobox": {
			"js": [
				"bentoanalytics"
			],
			"html": [
				"<!-- powered by bentobox"
			]
		},
		"ThriveCart": {
			"js": [
				"thrivecart"
			]
		},
		"HubSpot Chat": {
			"js": [
				"hubspotconversations"
			]
		},
		"Gravitec": {
			"js": [
				"gravitec",
				"gravitecwebpackjsonp"
			]
		},
		"Weebly": {
			"implies": [
				"PHP",
				"MySQL"
			],
			"js": [
				"_w.configdomain"
			]
		},
		"Ecwid": {
			"js": [
				"ecwid",
				"ecwidcart"
			]
		},
		"Mermaid": {
			"js": [
				"mermaid"
			],
			"html": [
				"<div [^>]*class=[\"']mermaid[\"']>"
			]
		},
		"MyCashFlow": {
			"headers": {
				"x-mcf-id": ""
			}
		},
		"Shopfa": {
			"headers": {
				"x-powered-by": "^shopfa ([\\d.]+)$"
			},
			"js": [
				"shopfa"
			],
			"meta": {
				"generator": [
					"^shopfa ([\\d.]+)$"
				]
			}
		},
		"CNZZ": {
			"js": [
				"cnzz_protocol"
			]
		},
		"LightMon Engine": {
			"cookies": {
				"lm_online": ""
			},
			"meta": {
				"generator": [
					"lightmon engine"
				]
			},
			"implies": [
				"PHP"
			],
			"html": [
				"<!-- lightmon engine copyright lightmon"
			]
		},
		"govCMS": {
			"meta": {
				"generator": [
					"drupal ([\\d]+) \\(http:\\\/\\\/drupal\\.org\\) \\+ govcms"
				]
			},
			"implies": [
				"Drupal"
			]
		},
		"FancyBox": {
			"implies": [
				"jQuery"
			],
			"js": [
				"$.fancybox.version"
			]
		},
		"Tengine": {
			"headers": {
				"server": "tengine"
			}
		},
		"GitLab CI\/CD": {
			"meta": {
				"description": [
					"gitlab ci\/cd is a tool built into gitlab for software development through continuous methodologies."
				]
			},
			"implies": [
				"Ruby on Rails"
			]
		},
		"Shuttle": {
			"implies": [
				"Laravel",
				"PHP",
				"Amazon Web Services"
			],
			"js": [
				"shuttle.frontapp"
			]
		},
		"VirtueMart": {
			"implies": [
				"Joomla"
			],
			"html": [
				"<div id=\"vmmainpage"
			]
		},
		"Jenkins": {
			"js": [
				"jenkinsciglobal",
				"jenkinsrules"
			],
			"headers": {
				"x-jenkins": "([\\d.]+)"
			},
			"html": [
				"<span class=\"jenkins_ver\"><a href=\"https:\/\/jenkins\\.io\/\">jenkins ver\\. ([\\d.]+)"
			],
			"implies": [
				"Java"
			]
		},
		"CartStack": {
			"js": [
				"_cartstack"
			]
		},
		"Play": {
			"cookies": {
				"play_session": ""
			},
			"implies": [
				"Scala"
			]
		},
		"CloudCart": {
			"meta": {
				"author": [
					"^cloudcart llc$"
				]
			}
		},
		"Chevereto": {
			"meta": {
				"generator": [
					"^chevereto ?([0-9.]+)?$"
				]
			},
			"html": [
				"powered by <a href=\"https?:\/\/chevereto\\.com\">"
			],
			"implies": [
				"PHP"
			]
		},
		"Elm-ui": {
			"implies": [
				"Elm"
			],
			"html": [
				"<style>[\\s\\s]*\\.explain > \\.s[\\s\\s]*\\.explain > \\.ctr > \\.s"
			]
		},
		"iWeb": {
			"meta": {
				"generator": [
					"^iweb( [\\d.]+)?"
				]
			}
		},
		"OneAPM": {
			"js": [
				"bweum"
			]
		},
		"GoAhead": {
			"headers": {
				"server": "goahead"
			}
		},
		"Hogan.js": {
			"js": [
				"hogan"
			]
		},
		"Dojo": {
			"js": [
				"dojo.version.major",
				"dojo"
			]
		},
		"Skedify": {
			"js": [
				"skedify.plugin.version"
			]
		},
		"Riskified": {
			"headers": {
				"server": "riskified server"
			},
			"js": [
				"riskx",
				"riskifiedbeaconload"
			],
			"html": [
				"<[^>]*beacon\\.riskified\\.com",
				"<[^>]*c\\.riskified\\.com"
			]
		},
		"JavaServer Faces": {
			"headers": {
				"x-powered-by": "jsf(?:\/([\\d.]+))?"
			},
			"implies": [
				"Java"
			]
		},
		"Koken": {
			"cookies": {
				"koken_referrer": ""
			},
			"meta": {
				"generator": [
					"koken ([\\d.]+)"
				]
			},
			"implies": [
				"PHP",
				"MySQL"
			],
			"html": [
				"<html lang=\"en\" class=\"k-source-essays k-lens-essays\">",
				"<!--\\s+koken debugging"
			]
		},
		"Shiny": {
			"js": [
				"shiny.addcustommessagehandler"
			]
		},
		"Borlabs Cookie": {
			"implies": [
				"WordPress"
			],
			"js": [
				"borlabscookieconfig"
			]
		},
		"mod_python": {
			"headers": {
				"server": "mod_python(?:\/([\\d.]+))?"
			},
			"implies": [
				"Python",
				"Apache"
			]
		},
		"osCommerce": {
			"cookies": {
				"oscsid": ""
			},
			"html": [
				"<br \/>powered by <a href=\"https?:\/\/www\\.oscommerce\\.com",
				"<(?:input|a)[^>]+name=\"oscsid\"",
				"<(?:tr|td|table)class=\"[^\"]*infoboxheading"
			],
			"implies": [
				"PHP",
				"MySQL"
			]
		},
		"AsciiDoc": {
			"meta": {
				"generator": [
					"^asciidoc ([\\d.]+)"
				]
			},
			"js": [
				"asciidoc"
			]
		},
		"WebEngage": {
			"js": [
				"webengage.__v"
			]
		},
		"Azure": {
			"cookies": {
				"arraffinity": ""
			},
			"headers": {
				"azure-version": ""
			}
		},
		"ELOG": {
			"html": [
				"<title>elog logbook selection<\/title>"
			]
		},
		"EPages": {
			"headers": {
				"x-epages-requestid": ""
			},
			"js": [
				"epages"
			]
		},
		"Bonfire": {
			"cookies": {
				"bf_session": ""
			},
			"html": [
				"powered by <a[^>]+href=\"https?:\/\/(?:www\\.)?cibonfire\\.com[^>]*>bonfire v([^<]+)"
			],
			"implies": [
				"CodeIgniter"
			]
		},
		"XenForo": {
			"cookies": {
				"xf_csrf": ""
			},
			"js": [
				"xf.guestusername"
			],
			"implies": [
				"PHP",
				"MySQL"
			],
			"html": [
				"(?:jquery\\.extend\\(true, xenforo|<a[^>]+>forum software by xenforo™|<!--xf:branding|<html[^>]+id=\"xenforo\")",
				"<html id=\"xf\" "
			]
		},
		"OneSignal": {
			"js": [
				"onesignal",
				"__onesignalsdkloadcount"
			]
		},
		"osTicket": {
			"cookies": {
				"ostsessid": ""
			},
			"implies": [
				"PHP",
				"MySQL"
			]
		},
		"Quantcast Choice": {
			"js": [
				"quantserve"
			]
		},
		"JoomShopping": {
			"implies": [
				"Joomla"
			],
			"js": [
				"joomshoppingvideohtml5"
			]
		},
		"OpenUI5": {
			"js": [
				"sap.ui.version"
			]
		},
		"Neto": {
			"js": [
				"neto"
			]
		},
		"Adverticum": {
			"html": [
				"<div (?:id=\"[a-za-z0-9_]*\" )?class=\"goadverticum\""
			]
		},
		"OpenGSE": {
			"headers": {
				"server": "gse"
			},
			"implies": [
				"Java"
			]
		},
		"Ionicons": {
			"html": [
				"<link[^>]* href=[^>]+ionicons(?:\\.min)?\\.css"
			]
		},
		"Irroba": {
			"html": [
				"<a[^>]*href=\"https:\/\/www\\.irroba\\.com\\.br"
			]
		},
		"Sensors Data": {
			"cookies": {
				"sensorsdata2015jssdkcross": ""
			},
			"js": [
				"sensorsdata_app_js_bridge_call_js",
				"sa.lib_version"
			]
		},
		"cPanel": {
			"cookies": {
				"cprelogin": ""
			},
			"headers": {
				"server": "cpsrvd\/([\\d.]+)"
			},
			"html": [
				"<!-- cpanel"
			]
		},
		"Ometria": {
			"cookies": {
				"ometria": ""
			},
			"js": [
				"addometriabasket",
				"addometriaidentify",
				"ometria"
			]
		},
		"phpPgAdmin": {
			"implies": [
				"PHP"
			],
			"html": [
				"(?:<title>phppgadmin<\/title>|<span class=\"appname\">phppgadmin)"
			]
		},
		"Omnisend": {
			"cookies": {
				"omnisendsessionid": ""
			},
			"js": [
				"_omnisend"
			],
			"meta": {
				"omnisend-site-verification": [

				]
			}
		},
		"Amazon S3": {
			"headers": {
				"server": "^amazons3$"
			},
			"implies": [
				"Amazon Web Services"
			]
		},
		"Wikinggruppen": {
			"html": [
				"<!-- wikinggruppen"
			]
		},
		"Yahoo Advertising": {
			"js": [
				"adxinserthtml"
			],
			"html": [
				"<iframe[^>]+adserver\\.yahoo\\.com",
				"<img[^>]+clicks\\.beap\\.bc\\.yahoo\\.com"
			]
		},
		"Akamai Bot Manager": {
			"cookies": {
				"ak_bmsc": ""
			},
			"implies": [
				"Akamai"
			]
		},
		"SobiPro": {
			"implies": [
				"Joomla"
			],
			"js": [
				"sobiprourl"
			]
		},
		"Synology DiskStation": {
			"meta": {
				"application-name": [
					"synology diskstation"
				],
				"description": [
					"^diskstation provides a full-featured network attached storage"
				]
			},
			"html": [
				"<noscript><div class='syno-no-script'"
			]
		},
		"CppCMS": {
			"headers": {
				"x-powered-by": "^cppcms\/([\\d.]+)$"
			}
		},
		"mod_rails": {
			"headers": {
				"x-powered-by": "mod_rails(?:\/([\\d.]+))?",
				"server": "mod_rails(?:\/([\\d.]+))?"
			},
			"implies": [
				"Ruby on Rails",
				"Apache"
			]
		},
		"Less": {
			"html": [
				"<link[^>]+ rel=\"stylesheet\/less\""
			]
		},
		"Graffiti CMS": {
			"cookies": {
				"graffitibot": ""
			},
			"meta": {
				"generator": [
					"graffiti cms ([^\"]+)"
				]
			},
			"implies": [
				"Microsoft ASP.NET"
			]
		},
		"SimpleHTTP": {
			"headers": {
				"server": "simplehttp(?:\/([\\d.]+))?"
			}
		},
		"Cloudinary": {
			"html": [
				"<img[^>]+\\.cloudinary\\.com"
			]
		},
		"INFOnline": {
			"js": [
				"iam_data",
				"szmvars"
			]
		},
		"GitBook": {
			"meta": {
				"generator": [
					"gitbook ([\\d.]+)?"
				]
			},
			"html": [
				"content=\"gitbook",
				"gitbook"
			]
		},
		"SkyVerge": {
			"implies": [
				"WooCommerce"
			],
			"js": [
				"sv_wc_payment_gateway_payment_form_param"
			]
		},
		"Classy": {
			"js": [
				"classy"
			]
		},
		"Adobe Experience Platform Launch": {
			"js": [
				"_satellite.buildinfo"
			]
		},
		"Chili Piper": {
			"js": [
				"chilipiper"
			]
		},
		"HP Compact Server": {
			"headers": {
				"server": "hp_compact_server(?:\/([\\d.]+))?"
			}
		},
		"ClickHeat": {
			"implies": [
				"PHP"
			],
			"js": [
				"clickheatserver"
			]
		},
		"Aimtell": {
			"js": [
				"_aimtellload",
				"_aimtellpushtoken",
				"_aimtellwebhook"
			]
		},
		"BigDump": {
			"implies": [
				"MySQL",
				"PHP"
			],
			"html": [
				"<!-- <h1>bigdump: staggered mysql dump importer ver\\. ([\\d.b]+)"
			]
		},
		"Rakuten": {
			"cookies": {
				"rakuten-source": ""
			},
			"js": [
				"rakutenranmid",
				"rakutensource"
			]
		},
		"jQuery": {
			"js": [
				"jquery.fn.jquery"
			]
		},
		"Brownie": {
			"headers": {
				"x-powered-by": "brownie"
			},
			"implies": [
				"PHP",
				"MySQL",
				"Amazon Web Services",
				"Bootstrap",
				"jQuery"
			]
		},
		"DataLife Engine": {
			"meta": {
				"generator": [
					"datalife engine"
				]
			},
			"js": [
				"dle_root"
			],
			"implies": [
				"PHP",
				"Apache"
			]
		},
		"Ionic": {
			"js": [
				"ionic.config",
				"ionic.version"
			]
		},
		"Open Journal Systems": {
			"cookies": {
				"ojssid": ""
			},
			"meta": {
				"generator": [
					"open journal systems(?: ([\\d.]+))?"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"Bugzilla": {
			"cookies": {
				"bugzilla_login_request_cookie": ""
			},
			"meta": {
				"generator": [
					"bugzilla ?([\\d.]+)?"
				]
			},
			"js": [
				"bugzilla"
			],
			"implies": [
				"Perl"
			],
			"html": [
				"href=\"enter_bug\\.cgi\">",
				"<main id=\"bugzilla-body\"",
				"<a href=\"https?:\/\/www\\.bugzilla\\.org\/docs\/([0-9.]+)\/[^>]+>help<",
				"<span id=\"information\" class=\"header_addl_info\">version ([\\d.]+)<"
			]
		},
		"Starlet": {
			"headers": {
				"server": "^plack::handler::starlet"
			},
			"implies": [
				"Perl"
			]
		},
		"Phusion Passenger": {
			"headers": {
				"server": "phusion passenger ([\\d.]+)",
				"x-powered-by": "phusion passenger ?([\\d.]+)?"
			}
		},
		"Roadiz CMS": {
			"headers": {
				"x-powered-by": "roadiz cms"
			},
			"meta": {
				"generator": [
					"^roadiz ?(?:master|develop)? v?([0-9\\.]+)"
				]
			},
			"implies": [
				"PHP",
				"Symfony"
			]
		},
		"MooTools": {
			"js": [
				"mootools",
				"mootools.version"
			]
		},
		"CKEditor": {
			"js": [
				"ckeditor",
				"ckeditor.version",
				"ckeditor_basepath"
			]
		},
		"AlloyUI": {
			"implies": [
				"Bootstrap",
				"YUI"
			],
			"js": [
				"aui"
			]
		},
		"Amazon Pay": {
			"js": [
				"amazonpayments",
				"offamazonpayments",
				"enableamazonpay",
				"onamazonpaymentsready"
			]
		},
		"Haravan": {
			"js": [
				"haravan"
			]
		},
		"Scientific Linux": {
			"headers": {
				"server": "scientific linux",
				"x-powered-by": "scientific linux"
			}
		},
		"Heap": {
			"js": [
				"heap.version.heapjsversion"
			]
		},
		"Gerrit": {
			"meta": {
				"title": [
					"^gerrit code review$"
				]
			},
			"js": [
				"gerrit",
				"gerrit_ui"
			],
			"implies": [
				"Java",
				"git"
			],
			"html": [
				">gerrit code review<\/a>\\s*\"\\s*\\(([0-9.]+)\\)",
				"<(?:div|style) id=\"gerrit_"
			]
		},
		"styled-components": {
			"implies": [
				"React"
			],
			"js": [
				"styled"
			]
		},
		"user.com": {
			"js": [
				"userengage"
			],
			"html": [
				"<div[^>]+\/id=\"ue_widget\""
			]
		},
		"Duda": {
			"js": [
				"systemid",
				"version"
			],
			"html": [
				"<div[^>]*id=\"p6irybw0wu\""
			]
		},
		"Wolf CMS": {
			"implies": [
				"PHP"
			],
			"html": [
				"(?:<a href=\"[^>]+wolfcms\\.org[^>]+>wolf cms(?:<\/a>)? inside|thank you for using <a[^>]+>wolf cms)"
			]
		},
		"SpotX": {
			"js": [
				"spotx.version"
			]
		},
		"PrestaShop": {
			"cookies": {
				"prestashop": ""
			},
			"meta": {
				"generator": [
					"prestashop"
				]
			},
			"js": [
				"freeproducttranslation",
				"prestashop",
				"pricedisplaymethod",
				"pricedisplayprecision",
				"rcanalyticsevents.eventprestashopcheckout"
			],
			"headers": {
				"powered-by": "^prestashop$"
			},
			"html": [
				"powered by <a\\s+[^>]+>prestashop",
				"<!-- \/block [a-z ]+ module (?:header|top)?\\s?-->",
				"<!-- \/module block [a-z ]+ -->"
			],
			"implies": [
				"PHP",
				"MySQL"
			]
		},
		"TwistPHP": {
			"headers": {
				"x-powered-by": "twistphp"
			},
			"implies": [
				"PHP"
			]
		},
		"Squarespace": {
			"headers": {
				"x-servedby": "squarespace"
			},
			"js": [
				"squarespace",
				"static.squarespace_context"
			],
			"html": [
				"<!-- this is squarespace\\. -->"
			]
		},
		"Loja Virtual": {
			"js": [
				"link_loja_virtual",
				"loja_sem_dominio",
				"id_loja_virtual"
			]
		},
		"Textpattern CMS": {
			"meta": {
				"generator": [
					"textpattern"
				]
			},
			"implies": [
				"PHP",
				"MySQL"
			]
		},
		"Twilight CMS": {
			"headers": {
				"x-powered-cms": "twilight cms"
			}
		},
		"Vigbo": {
			"cookies": {
				"_gphw_mode": ""
			},
			"html": [
				"<link[^>]* href=[^>]+(?:\\.vigbo\\.com|\\.gophotoweb\\.com)"
			]
		},
		"Peek": {
			"js": [
				"peekjsapi",
				"_peekconfig",
				"peek"
			]
		},
		"Shoplo": {
			"js": [
				"shoploajax"
			]
		},
		"Gallery": {
			"js": [
				"$.fn.gallery_valign",
				"galleryauthtoken"
			],
			"html": [
				"<div id=\"gsnavbar\" class=\"gcborder1\">",
				"<a href=\"http:\/\/gallery\\.sourceforge\\.net\"><img[^>]+powered by gallery\\s*(?:(?:v|version)\\s*([0-9.]+))?"
			]
		},
		"Babel": {
			"js": [
				"_babelpolyfill"
			]
		},
		"TotalCode": {
			"headers": {
				"x-powered-by": "^totalcode$"
			}
		},
		"Zepto": {
			"js": [
				"zepto"
			]
		},
		"Permutive": {
			"js": [
				"permutive"
			]
		},
		"Varnish": {
			"headers": {
				"x-varnish-action": ""
			}
		},
		"GOV.UK Elements": {
			"implies": [
				"GOV.UK Toolkit"
			],
			"html": [
				"<link[^>]+elements-page[^>\"]+css",
				"<div[^>]+phase-banner-alpha",
				"<div[^>]+phase-banner-beta",
				"<div[^>]+govuk-box-highlight"
			]
		},
		"Strikingly": {
			"html": [
				"<!-- powered by strikingly\\.com"
			]
		},
		"Karma": {
			"implies": [
				"Node.js"
			],
			"js": [
				"karma.vars.version"
			]
		},
		"Segment": {
			"js": [
				"analytics.version"
			]
		},
		"Coinimp": {
			"js": [
				"client.anonymous"
			]
		},
		"Yahoo! Ecommerce": {
			"headers": {
				"x-xrds-location": "\/ystore\/"
			},
			"js": [
				"ystore"
			],
			"html": [
				"<link[^>]+store\\.yahoo\\.net"
			]
		},
		"Drift": {
			"js": [
				"drift",
				"driftt"
			]
		},
		"FAST Search for SharePoint": {
			"implies": [
				"Microsoft SharePoint",
				"Microsoft ASP.NET"
			],
			"html": [
				"<input[^>]+ name=\"parametricsearch"
			]
		},
		"KQS.store": {
			"js": [
				"kqs_box",
				"kqs_off"
			]
		},
		"Arc": {
			"js": [
				"arc.p2pclient",
				"arcwidgetjsonp"
			]
		},
		"e107": {
			"cookies": {
				"e107_tz": ""
			},
			"headers": {
				"x-powered-by": "e107"
			},
			"implies": [
				"PHP"
			]
		},
		"Tealeaf": {
			"js": [
				"tealeaf"
			]
		},
		"Highcharts": {
			"js": [
				"highcharts",
				"highcharts.version"
			],
			"html": [
				"<svg[^>]*><desc>created with highcharts ([\\d.]*)"
			]
		},
		"Concrete5": {
			"cookies": {
				"concrete5": ""
			},
			"meta": {
				"generator": [
					"^concrete5 - ([\\d.]+)$"
				]
			},
			"js": [
				"ccm_image_path"
			],
			"implies": [
				"PHP"
			]
		},
		"phpDocumentor": {
			"implies": [
				"PHP"
			],
			"html": [
				"<!-- generated by phpdocumentor"
			]
		},
		"Svbtle": {
			"meta": {
				"generator": [
					"^svbtle\\.com$"
				]
			}
		},
		"Apple Pay": {
			"js": [
				"applepay",
				"enableapplepay"
			],
			"html": [
				"<[^>]+aria-labelledby=\"pi-apple_pay",
				"<script id=\"apple-pay"
			]
		},
		"MyWebsite": {
			"meta": {
				"generator": [
					"^.*mywebsite.*$"
				]
			},
			"js": [
				"systemid",
				"version"
			]
		},
		"eSyndiCat": {
			"meta": {
				"generator": [
					"^esyndicat "
				]
			},
			"js": [
				"esyndicat"
			],
			"headers": {
				"x-drectory-script": "^esyndicat"
			},
			"implies": [
				"PHP"
			]
		},
		"Statamic": {
			"headers": {
				"x-powered-by": "^statamic$"
			},
			"implies": [
				"PHP",
				"Laravel"
			]
		},
		"Question2Answer": {
			"implies": [
				"PHP"
			],
			"html": [
				"<!-- powered by question2answer"
			]
		},
		"Epom": {
			"js": [
				"epomcustomparams"
			]
		},
		"phpMyAdmin": {
			"implies": [
				"PHP",
				"MySQL"
			],
			"js": [
				"pma_absolute_uri"
			],
			"html": [
				"!\\[cdata\\[[^<]*pma_version:\\\"([\\d.]+)",
				"(?: \\| phpmyadmin ([\\d.]+)<\\\/title>|pma_sendheaderlocation\\(|<link [^>]*href=\"[^\"]*phpmyadmin\\.css\\.php)"
			]
		},
		"Wair": {
			"js": [
				"predictwidget",
				"predictv3.default.version"
			]
		},
		"Recart": {
			"js": [
				"__recart",
				"recart"
			]
		},
		"TurfJS": {
			"js": [
				"turf.feature",
				"turf.point",
				"turf.random"
			]
		},
		"Intel Active Management Technology": {
			"headers": {
				"server": "intel\\(r\\) active management technology(?: ([\\d.]+))?"
			}
		},
		"SmartSite": {
			"meta": {
				"author": [
					"redacteur smartinstant"
				]
			},
			"html": [
				"<[^>]+\/smartsite\\.(?:dws|shtml)\\?id="
			]
		},
		"Vidazoo": {
			"js": [
				"__vidazooplayer__",
				"vidazoo",
				"vidazoo.version"
			]
		},
		"Kinsta": {
			"headers": {
				"x-kinsta-cache": ""
			},
			"implies": [
				"WordPress"
			]
		},
		"Gridsome": {
			"meta": {
				"generator": [
					"^gridsome v([\\d.]+)$"
				]
			},
			"implies": [
				"Vue.js"
			]
		},
		"Blogger": {
			"meta": {
				"generator": [
					"^blogger$"
				]
			},
			"implies": [
				"Python"
			]
		},
		"phpBB": {
			"cookies": {
				"phpbb": ""
			},
			"meta": {
				"copyright": [
					"phpbb group"
				]
			},
			"js": [
				"style_cookie_settings",
				"phpbb"
			],
			"implies": [
				"PHP"
			],
			"html": [
				"powered by <a[^>]+phpbb",
				"<div class=phpbb_copyright>",
				"<[^>]+styles\/(?:sub|pro)silver\/theme",
				"<img[^>]+i_icon_mini",
				"<table class=\"[^\"]*forumline"
			]
		},
		"Bubble": {
			"headers": {
				"x-bubble-capacity-limit": ""
			},
			"js": [
				"bubble_environment",
				"bubble_hostname_modifier",
				"bubble_version",
				"_bubble_page_load_data"
			],
			"implies": [
				"Node.js"
			]
		},
		"SAP Commerce Cloud": {
			"cookies": {
				"_hybris": ""
			},
			"html": [
				"<[^>]+\/(?:sys_master|hybr|_ui\/(?:.*responsive\/)?(?:desktop|common(?:\/images|\/img|\/css|ico)?))\/",
				"<script[^>].*hybris.*.js"
			],
			"implies": [
				"Java"
			]
		},
		"iEXExchanger": {
			"cookies": {
				"iexexchanger_session": ""
			},
			"meta": {
				"generator": [
					"iexexchanger"
				]
			},
			"implies": [
				"PHP",
				"Apache",
				"Angular"
			]
		},
		"Bsale": {
			"cookies": {
				"_bsalemarket_session": ""
			},
			"meta": {
				"autor": [
					"bsale"
				],
				"generator": [
					"bsale"
				]
			},
			"js": [
				"bsale.version"
			],
			"implies": [
				"Nginx"
			]
		},
		"FrontPage": {
			"meta": {
				"generator": [
					"microsoft frontpage(?:\\s((?:express )?[\\d.]+))?"
				],
				"progid": [
					"^frontpage\\."
				]
			}
		},
		"JavaServer Pages": {
			"headers": {
				"x-powered-by": "jsp(?:\/([\\d.]+))?"
			},
			"implies": [
				"Java"
			]
		},
		"W3 Total Cache": {
			"headers": {
				"x-powered-by": "w3 total cache(?:\/([\\d.]+))?"
			},
			"html": [
				"<!--[^>]+w3 total cache"
			],
			"implies": [
				"WordPress"
			]
		},
		"NVD3": {
			"implies": [
				"D3"
			],
			"js": [
				"nv.addgraph",
				"nv.version"
			],
			"html": [
				"<link[^>]* href=[^>]+nv\\.d3(?:\\.min)?\\.css"
			]
		},
		"Chargebee": {
			"js": [
				"chargebeetrackfunc",
				"chargebee"
			]
		},
		"Pure CSS": {
			"html": [
				"<link[^>]+(?:([\\d.])+\/)?pure(?:-min)?\\.css",
				"<div[^>]+class=\"[^\"]*pure-u-(?:sm-|md-|lg-|xl-)?\\d-\\d"
			]
		},
		"Storeden": {
			"headers": {
				"x-powered-by": "storeden"
			}
		},
		"Instapage": {
			"implies": [
				"Lua",
				"Node.js"
			],
			"js": [
				"instapagesp",
				"_instapagesnowplow"
			]
		},
		"CacheFly": {
			"headers": {
				"server": "^cfs ",
				"x-cf1": ""
			}
		},
		"Bolt CMS": {
			"meta": {
				"generator": [
					"bolt"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"Crazy Egg": {
			"js": [
				"ce2"
			]
		},
		"Sana Commerce": {
			"js": [
				"sana.ui"
			]
		},
		"Cloudflare": {
			"cookies": {
				"__cfduid": ""
			},
			"js": [
				"cloudflare"
			],
			"headers": {
				"server": "^cloudflare$",
				"cf-cache-status": ""
			}
		},
		"WebMetric": {
			"cookies": {
				"_wmuid": ""
			},
			"js": [
				"_wmid"
			]
		},
		"Lift": {
			"headers": {
				"x-lift-version": "(.+)"
			},
			"implies": [
				"Scala"
			]
		},
		"LinkSmart": {
			"js": [
				"_mb_site_guid",
				"ls_json",
				"linksmart"
			]
		},
		"Warp": {
			"headers": {
				"server": "^warp\/(\\d+(?:\\.\\d+)+)?$"
			},
			"implies": [
				"Haskell"
			]
		},
		"Atlassian FishEye": {
			"cookies": {
				"fesessionid": ""
			},
			"html": [
				"<title>(?:log in to )?fisheye (?:and crucible )?([\\d.]+)?<\/title>"
			]
		},
		"a-blog cms": {
			"meta": {
				"generator": [
					"a-blog cms"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"Nuxt.js": {
			"implies": [
				"Vue.js",
				"Node.js"
			],
			"js": [
				"$nuxt"
			],
			"html": [
				"<div [^>]*id=\"__nuxt\"",
				"<script [^>]*>window\\.__nuxt__"
			]
		},
		"Komodo CMS": {
			"meta": {
				"generator": [
					"^komodo cms"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"Titan": {
			"js": [
				"titan",
				"titanenabled"
			]
		},
		"SweetAlert2": {
			"js": [
				"sweetalert2"
			],
			"html": [
				"<link[^>]+?href=\"[^\"]+sweetalert2(?:\\.min)?\\.css"
			]
		},
		"Centminmod": {
			"headers": {
				"x-powered-by": "centminmod"
			},
			"implies": [
				"CentOS",
				"Nginx",
				"PHP"
			]
		},
		"Adobe Target": {
			"js": [
				"adobe.target.version",
				"adobe.target"
			]
		},
		"Pure Chat": {
			"js": [
				"pcwidget",
				"purechatapi"
			]
		},
		"Django": {
			"implies": [
				"Python"
			],
			"js": [
				"__admin_media_prefix__",
				"django"
			],
			"html": [
				"csrfmiddlewaretoken",
				"(?:powered by <a[^>]+>django ?([\\d.]+)?<\\\/a>|<input[^>]*name=[\"']csrfmiddlewaretoken[\"'][^>]*>)"
			]
		},
		"Yieldify": {
			"js": [
				"_yieldify"
			]
		},
		"Ametys": {
			"meta": {
				"generator": [
					"(?:ametys|anyware technologies)"
				]
			},
			"implies": [
				"Java"
			]
		},
		"SEMrush": {
			"js": [
				"semrush"
			]
		},
		"Salesforce": {
			"cookies": {
				"com.salesforce": ""
			},
			"js": [
				"sfdcapp",
				"sfdccmp",
				"sfdcpage",
				"sfdcsessionvars"
			],
			"html": [
				"<[^>]+=\"brandquaternaryfgrs\""
			]
		},
		"Resengo": {
			"js": [
				"wpjsonpresengoreservationwidget"
			]
		},
		"Splunk": {
			"meta": {
				"author": [
					"splunk inc"
				]
			},
			"html": [
				"<p class=\"footer\">&copy; [-\\d]+ splunk inc\\.(?: splunk ([\\d\\.]+(?: build [\\d\\.]*\\d)?))?[^<]*<\/p>"
			]
		},
		"SweetAlert": {
			"html": [
				"<link[^>]+?href=\"[^\"]+sweet-alert(?:\\.min)?\\.css"
			]
		},
		"Sellacious": {
			"implies": [
				"Joomla"
			],
			"js": [
				"sellaciousviewcartaio"
			]
		},
		"Google Web Server": {
			"headers": {
				"server": "gws"
			}
		},
		"ConvertFlow": {
			"js": [
				"convertflow"
			]
		},
		"HiConversion": {
			"js": [
				"__hic.version"
			]
		},
		"Sitefinity": {
			"meta": {
				"generator": [
					"^sitefinity (.+)$"
				]
			},
			"implies": [
				"Microsoft ASP.NET"
			]
		},
		"EKM": {
			"cookies": {
				"ekmpowershop": ""
			},
			"js": [
				"_ekmpinpoint"
			]
		},
		"Dancer": {
			"headers": {
				"server": "perl dancer ([\\d.]+)",
				"x-powered-by": "perl dancer ([\\d.]+)"
			},
			"implies": [
				"Perl"
			]
		},
		"OpenGrok": {
			"cookies": {
				"opengrok": ""
			},
			"meta": {
				"generator": [
					"opengrok(?: v?([\\d.]+))?"
				]
			},
			"implies": [
				"Java"
			]
		},
		"Stack Analytix": {
			"js": [
				"stackanalysis"
			]
		},
		"XMB": {
			"html": [
				"<!-- powered by xmb"
			]
		},
		"Stackla": {
			"js": [
				"stackla"
			]
		},
		"Sympa": {
			"meta": {
				"generator": [
					"^sympa$"
				]
			},
			"html": [
				"<a href=\"https?:\/\/www\\.sympa\\.org\">\\s*powered by sympa\\s*<\/a>"
			],
			"implies": [
				"Perl"
			]
		},
		"BrightInfo": {
			"js": [
				"bijsurl",
				"_bi_",
				"_biq"
			]
		},
		"Fomo": {
			"js": [
				"fomo.version"
			]
		},
		"Kooboo CMS": {
			"headers": {
				"x-kooboocms-version": "^(.+)$"
			},
			"implies": [
				"Microsoft ASP.NET"
			]
		},
		"OneStat": {
			"js": [
				"onestat_pageview"
			]
		},
		"NetSuite": {
			"cookies": {
				"ns_ver": ""
			}
		},
		"GoJS": {
			"js": [
				"go.graphobject",
				"go.version"
			]
		},
		"Apache Tomcat": {
			"html": [
				"<h3>apache tomcat.*?</h3>"
			],
			"headers": {
				"server": "^apache-coyote",
				"x-powered-by": "\\btomcat\\b(?:-([\\d.]+))?"
			},
			"implies": [
				"Java"
			]
		},
		"ColorMeShop": {
			"js": [
				"colorme"
			]
		},
		"Shoppy": {
			"js": [
				"shoppy"
			]
		},
		"Haddock": {
			"html": [
				"<p>produced by <a href=\"http:\/\/www\\.haskell\\.org\/haddock\/\">haddock<\/a> version ([0-9.]+)<\/p>"
			]
		},
		"Pagekit": {
			"meta": {
				"generator": [
					"pagekit"
				]
			}
		},
		"AOLserver": {
			"headers": {
				"server": "aolserver\/?([\\d.]+)?"
			}
		},
		"Pimcore": {
			"headers": {
				"x-powered-by": "^pimcore$"
			},
			"implies": [
				"PHP"
			]
		},
		"FirstImpression.io": {
			"js": [
				"fiprebidanalyticshandler",
				"fi.options"
			]
		},
		"Oracle Commerce": {
			"headers": {
				"x-atg-version": "(?:atgplatform\/([\\d.]+))?"
			}
		},
		"SaleCycle": {
			"html": [
				"<iframe[^>]+title=\"salecycle\"[^>]+src=\"[^>]+salecycle\\.com"
			]
		},
		"SegmentStream": {
			"js": [
				"segmentstream.version"
			]
		},
		"Sarka-SPIP": {
			"meta": {
				"generator": [
					"sarka-spip(?:\\s([\\d.]+))?"
				]
			},
			"implies": [
				"SPIP"
			]
		},
		"Twitter Emoji (Twemoji)": {
			"js": [
				"twemoji"
			]
		},
		"Posterous": {
			"js": [
				"posterous"
			],
			"html": [
				"<div class=\"posterous"
			]
		},
		"Google Web Toolkit": {
			"meta": {
				"gwt:property": [

				]
			},
			"js": [
				"__gwt_isknownpropertyvalue",
				"__gwt_stylesloaded",
				"__gwtlistener",
				"__gwt_",
				"__gwt_activemodules",
				"__gwt_getmetaproperty"
			],
			"implies": [
				"Java"
			]
		},
		"Lightspeed eCom": {
			"html": [
				"<!-- \\[start\\] 'blocks\/head\\.rain' -->"
			]
		},
		"decimal.js": {
			"js": [
				"decimal.round_half_floor"
			]
		},
		"Cargo": {
			"meta": {
				"cargo_title": [

				]
			},
			"html": [
				"<link [^>]+cargo feed"
			],
			"implies": [
				"PHP"
			]
		},
		"Criteo": {
			"js": [
				"criteo",
				"criteo_pubtag",
				"criteo_q"
			]
		},
		"Pulse Secure": {
			"cookies": {
				"dssignin": ""
			}
		},
		"CakePHP": {
			"cookies": {
				"cakephp": ""
			},
			"meta": {
				"application-name": [
					"cakephp"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"AOS": {
			"js": [
				"aos.init",
				"aos.refresh",
				"aos.refreshhard"
			]
		},
		"MochiKit": {
			"js": [
				"mochikit",
				"mochikit.mochikit.version"
			]
		},
		"SeamlessCMS": {
			"meta": {
				"generator": [
					"^seamless\\.?cms"
				]
			}
		},
		"A8.net": {
			"js": [
				"a8salescookierepository",
				"a8sales",
				"map_a8"
			]
		},
		"Inveon": {
			"cookies": {
				"inv.customer": "",
				"inveonsessionid": ""
			},
			"js": [
				"invapp",
				"invtagmanagerparams"
			]
		},
		"RCMS": {
			"meta": {
				"generator": [
					"^(?:rcms|reallycms)"
				]
			}
		},
		"xtCommerce": {
			"meta": {
				"generator": [
					"xt:commerce"
				]
			},
			"html": [
				"<div class=\"copyright\">[^<]+<a[^>]+>xt:commerce"
			]
		},
		"Okta": {
			"js": [
				"oktaauth",
				"isoktaenabled",
				"oktacurrentsessionurl"
			]
		},
		"Pelican": {
			"implies": [
				"Python"
			],
			"html": [
				"powered by <a href=\"[^>]+getpelican\\.com",
				"powered by <a href=\"https?:\/\/pelican\\.notmyidea\\.org"
			]
		},
		"Klaviyo": {
			"js": [
				"klaviyosubscribe",
				"klaviyo"
			]
		},
		"WEBDEV": {
			"headers": {
				"webdevsrc": ""
			},
			"html": [
				"<!-- [a-za-z0-9_]+ [\\d\/]+ [\\d:]+ webdev \\d\\d ([\\d.]+) -->"
			],
			"meta": {
				"generator": [
					"^webdev$"
				]
			}
		},
		"Xanario": {
			"meta": {
				"generator": [
					"xanario shopsoftware"
				]
			}
		},
		"Splunkd": {
			"headers": {
				"server": "splunkd"
			}
		},
		"Kooomo": {
			"meta": {
				"generator": [
					"kooomo(?: v([\\d.]+))?"
				]
			},
			"implies": [
				"PHP",
				"MySQL"
			]
		},
		"Stimulus": {
			"html": [
				"<[^>]+data-controller"
			]
		},
		"Hammer.js": {
			"js": [
				"hammer.version",
				"ha.version",
				"hammer"
			]
		},
		"HCL Digital Experience": {
			"headers": {
				"itx-generated-timestamp": ""
			},
			"implies": [
				"Java"
			]
		},
		"Klevu": {
			"js": [
				"klevu_apikey",
				"klevu_layout",
				"klevu_sessionid"
			]
		},
		"WordPress Super Cache": {
			"headers": {
				"wp-super-cache": ""
			},
			"html": [
				"<!--[^>]+wp-super-cache"
			],
			"implies": [
				"WordPress"
			]
		},
		"gitlist": {
			"implies": [
				"PHP",
				"git"
			],
			"html": [
				"<p>powered by <a[^>]+>gitlist ([\\d.]+)"
			]
		},
		"SOBI 2": {
			"implies": [
				"Joomla"
			],
			"html": [
				"(?:<!-- start of sigsiu online business index|<div[^>]* class=\"sobi2)"
			]
		},
		"DERAK.CLOUD": {
			"cookies": {
				"__derak_auth": ""
			},
			"js": [
				"derakcloud.init"
			],
			"headers": {
				"derak-umbrage": ""
			}
		},
		"TWiki": {
			"cookies": {
				"twikisid": ""
			},
			"html": [
				"<img [^>]*(?:title|alt)=\"this site is powered by the twiki collaboration platform"
			],
			"implies": [
				"Perl"
			]
		},
		"MoinMoin": {
			"cookies": {
				"moin_session": ""
			},
			"js": [
				"show_switch2gui"
			],
			"implies": [
				"Python"
			]
		},
		"DirectAdmin": {
			"headers": {
				"server": "directadmin daemon v([\\d.]+)"
			},
			"html": [
				"<a[^>]+>directadmin<\/a> web control panel"
			],
			"implies": [
				"PHP",
				"Apache"
			]
		},
		"Gravatar": {
			"js": [
				"gravatar"
			],
			"html": [
				"<[^>]+gravatar\\.com\/avatar\/"
			]
		},
		"plentymarkets": {
			"headers": {
				"x-plenty-shop": ""
			},
			"meta": {
				"generator": [
					"plentymarkets"
				]
			}
		},
		"MaxSite CMS": {
			"meta": {
				"generator": [
					"maxsite cms"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"CherryPy": {
			"headers": {
				"server": "cherrypy(?:\/([\\d.]+))?"
			}
		},
		"BrowserCMS": {
			"meta": {
				"generator": [
					"browsercms ([\\d.]+)"
				]
			},
			"implies": [
				"Ruby"
			]
		},
		"Snowplow Analytics": {
			"cookies": {
				"sp": "",
				"_sp_id": ""
			},
			"js": [
				"globalsnowplownamespace",
				"snowplow"
			]
		},
		"Backbone.js": {
			"implies": [
				"Underscore.js"
			],
			"js": [
				"backbone",
				"backbone.version"
			]
		},
		"GOV.UK Template": {
			"js": [
				"govuk"
			],
			"html": [
				"<link[^>]+govuk-template[^>\"]+css",
				"<link[^>]+govuk-template-print[^>\"]+css",
				"<link[^>]+govuk-template-ie6[^>\"]+css",
				"<link[^>]+govuk-template-ie7[^>\"]+css",
				"<link[^>]+govuk-template-ie8[^>\"]+css"
			]
		},
		"Protovis": {
			"js": [
				"protovis"
			]
		},
		"Swell": {
			"cookies": {
				"swell-session": ""
			},
			"js": [
				"swell.version"
			],
			"html": [
				"<[^>]*swell\\.is",
				"<[^>]*swell\\.store",
				"<[^>]*schema\\.io"
			]
		},
		"Divi": {
			"js": [
				"divi"
			]
		},
		"FingerprintJS": {
			"js": [
				"fingerprint",
				"fingerprint2",
				"fingerprint2.version",
				"fingerprintjs"
			]
		},
		"Danneo CMS": {
			"headers": {
				"x-powered-by": "cms danneo ([\\d.]+)"
			},
			"meta": {
				"generator": [
					"danneo cms ([\\d.]+)"
				]
			},
			"implies": [
				"Apache",
				"PHP"
			]
		},
		"Abicart": {
			"meta": {
				"generator": [
					"abicart",
					"textalk webshop"
				]
			}
		},
		"Spring": {
			"headers": {
				"x-application-context": ""
			},
			"implies": [
				"Java"
			]
		},
		"Intercom Articles": {
			"html": [
				"<a href=\"https:\/\/www.intercom.com\/intercom-link[^\"]+solution=customer-support[^>]+>we run on intercom"
			]
		},
		"Kibana": {
			"headers": {
				"kbn-version": "^([\\d.]+)$",
				"kbn-name": "kibana"
			},
			"html": [
				"<title>kibana<\/title>"
			],
			"implies": [
				"Node.js",
				"Elasticsearch"
			]
		},
		"Vaadin": {
			"implies": [
				"Java"
			],
			"js": [
				"vaadin"
			]
		},
		"SoteShop": {
			"cookies": {
				"soteshop": "^\\w+$"
			},
			"implies": [
				"PHP"
			]
		},
		"EdgeCast": {
			"headers": {
				"server": "^ecd\\s\\(\\s+\\)"
			}
		},
		"Site Kit": {
			"meta": {
				"generator": [
					"^site kit by google ?([\\d.]+)?"
				]
			},
			"implies": [
				"WordPress"
			]
		},
		"Chartbeat": {
			"js": [
				"_sf_async_config",
				"_sf_endpt"
			]
		},
		"Tawk.to": {
			"cookies": {
				"tawkconnectiontime": ""
			}
		},
		"Zipkin": {
			"headers": {
				"x-b3-flags": ""
			}
		},
		"WebSite X5": {
			"meta": {
				"generator": [
					"incomedia website x5 (\\w+ [\\d.]+)"
				]
			}
		},
		"Beyable": {
			"cookies": {
				"beyable-cart": ""
			},
			"js": [
				"beyable",
				"beyabledomain",
				"beyablekey"
			]
		},
		"Amazon EC2": {
			"headers": {
				"server": "\\(amazon\\)"
			},
			"implies": [
				"Amazon Web Services"
			]
		},
		"VP-ASP": {
			"implies": [
				"Microsoft ASP.NET"
			],
			"html": [
				"<a[^>]+>powered by vp-asp shopping cart<\/a>"
			]
		},
		"Cherokee": {
			"headers": {
				"server": "^cherokee(?:\/([\\d.]+))?"
			}
		},
		"Fact Finder": {
			"html": [
				"<!-- factfinder"
			]
		},
		"GitHub Pages": {
			"headers": {
				"server": "^github\\.com$",
				"x-github-request-id": ""
			},
			"implies": [
				"Ruby on Rails"
			]
		},
		"Freshworks CRM": {
			"js": [
				"zarget",
				"zargetapi",
				"zargetform"
			]
		},
		"jComponent": {
			"implies": [
				"jQuery"
			],
			"js": [
				"main.version"
			]
		},
		"Zinnia": {
			"meta": {
				"generator": [
					"zinnia"
				]
			},
			"implies": [
				"Django"
			]
		},
		"iPresta": {
			"meta": {
				"designer": [
					"ipresta"
				]
			},
			"implies": [
				"PHP",
				"PrestaShop"
			]
		},
		"BittAds": {
			"js": [
				"bitt"
			]
		},
		"Handlebars": {
			"js": [
				"handlebars",
				"handlebars.version"
			],
			"html": [
				"<[^>]*type=[^>]text\\\/x-handlebars-template"
			]
		},
		"CloudSuite": {
			"cookies": {
				"cs_secure_session": ""
			}
		},
		"Virgool": {
			"headers": {
				"x-powered-by": "^virgool$"
			}
		},
		"Adabra": {
			"js": [
				"adabrapreview",
				"adabra_version_panel",
				"adabra_version_track"
			]
		},
		"AudioEye": {
			"html": [
				"<iframe[^>]*audioeye\\.com\/frame\/cookiestorage"
			]
		},
		"SPIP": {
			"headers": {
				"composed-by": "spip ([\\d.]+) @",
				"x-spip-cache": ""
			},
			"meta": {
				"generator": [
					"(?:^|\\s)spip(?:\\s([\\d.]+(?:\\s\\[\\d+\\])?))?"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"Autopilot": {
			"js": [
				"autopilot",
				"autopilotanywhere"
			]
		},
		"thttpd": {
			"headers": {
				"server": "\\bthttpd(?:\/([\\d.]+))?"
			}
		},
		"Apache Wicket": {
			"implies": [
				"Java"
			],
			"js": [
				"wicket"
			]
		},
		"Jirafe": {
			"js": [
				"jirafe"
			]
		},
		"Whooshkaa": {
			"html": [
				"<iframe src=\"[^>]+whooshkaa\\.com"
			]
		},
		"Ackee": {
			"js": [
				"ackeetracker"
			]
		},
		"Koala Framework": {
			"meta": {
				"generator": [
					"^koala web framework cms"
				]
			},
			"html": [
				"<!--[^>]+this website is powered by koala web framework cms"
			],
			"implies": [
				"PHP"
			]
		},
		"AWIN": {
			"cookies": {
				"bagawin": ""
			},
			"js": [
				"awin.tracking"
			]
		},
		"Bigware": {
			"cookies": {
				"bigwadminid": ""
			},
			"html": [
				"(?:diese <a href=[^>]+bigware\\.de|<a href=[^>]+\/main_bigware_\\d+\\.php)"
			],
			"implies": [
				"PHP"
			]
		},
		"Afterpay": {
			"js": [
				"afterpay",
				"afterpay_product"
			]
		},
		"Adnegah": {
			"headers": {
				"x-advertising-by": "adnegah\\.net"
			},
			"html": [
				"<iframe [^>]*src=\"[^\"]+adnegah\\.net"
			]
		},
		"AdonisJS": {
			"cookies": {
				"adonis-session": ""
			},
			"implies": [
				"Node.js"
			]
		},
		"MindBody": {
			"js": [
				"healcodewidget"
			]
		},
		"Webflow": {
			"meta": {
				"generator": [
					"webflow"
				]
			},
			"js": [
				"webflow"
			],
			"html": [
				"<html[^>]+data-wf-site"
			]
		},
		"Acuity Scheduling": {
			"js": [
				"acuity_modal_init"
			]
		},
		"Bablic": {
			"js": [
				"bablic"
			]
		},
		"TN Express Web": {
			"cookies": {
				"tnew": ""
			},
			"implies": [
				"Tessitura"
			]
		},
		"Shoptet": {
			"meta": {
				"web_author": [
					"^shoptet"
				]
			},
			"js": [
				"shoptet"
			],
			"implies": [
				"PHP"
			],
			"html": [
				"<link [^>]*href=\"https?:\/\/cdn\\.myshoptet\\.com\/"
			]
		},
		"TornadoServer": {
			"headers": {
				"server": "tornadoserver(?:\/([\\d.]+))?"
			}
		},
		"Pingoteam": {
			"meta": {
				"designer": [
					"pingoteam"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"Moguta.CMS": {
			"implies": [
				"PHP"
			],
			"html": [
				"<link[^>]+href=[\"'][^\"]+mg-(?:core|plugins|templates)\/"
			]
		},
		"WebsiteBaker": {
			"meta": {
				"generator": [
					"websitebaker"
				]
			},
			"implies": [
				"PHP",
				"MySQL"
			]
		},
		"pirobase CMS": {
			"implies": [
				"Java"
			],
			"html": [
				"<(?:script|link)[^>]\/site\/[a-z0-9\/._-]+\/resourcecached\/[a-z0-9\/._-]+",
				"<input[^>]+cbi:\/\/\/cms\/"
			]
		},
		"amCharts": {
			"js": [
				"amcharts"
			],
			"html": [
				"<svg[^>]*><desc>javascript chart by amcharts ([\\d.]*)"
			]
		},
		"NitroPack": {
			"meta": {
				"generator": [
					"nitropack"
				]
			}
		},
		"LocalFocus": {
			"implies": [
				"Angular",
				"D3"
			],
			"html": [
				"<iframe[^>]+\\blocalfocus\\b"
			]
		},
		"jQuery Mobile": {
			"implies": [
				"jQuery"
			],
			"js": [
				"jquery.mobile.version"
			]
		},
		"AT Internet XiTi": {
			"js": [
				"xt_click"
			]
		},
		"Java Servlet": {
			"headers": {
				"x-powered-by": "servlet(?:\\\/([\\d.]+))?"
			},
			"implies": [
				"Java"
			]
		},
		"Mongrel": {
			"headers": {
				"server": "mongrel"
			},
			"implies": [
				"Ruby"
			]
		},
		"Meebo": {
			"html": [
				"(?:<iframe id=\"meebo-iframe\"|meebo\\('domready'\\))"
			]
		},
		"GoDaddy Website Builder": {
			"cookies": {
				"dps_site_id": ""
			},
			"meta": {
				"generator": [
					"go daddy website builder (.+)"
				]
			}
		},
		"Contensis": {
			"meta": {
				"generator": [
					"contensis cms version ([\\d.]+)"
				]
			},
			"implies": [
				"Java",
				"CFML"
			]
		},
		"Matomo Analytics": {
			"cookies": {
				"piwik_sessid": ""
			},
			"js": [
				"matomo",
				"piwik",
				"_paq"
			],
			"meta": {
				"google-play-app": [
					"app-id=org\\.piwik\\.mobile2"
				],
				"apple-itunes-app": [
					"app-id=737216887"
				],
				"generator": [
					"(?:matomo|piwik) - open source web analytics"
				]
			}
		},
		"Venmo": {
			"html": [
				"<[^>]+aria-labelledby=\"pi-venmo"
			]
		},
		"Xitami": {
			"headers": {
				"server": "xitami(?:\/([\\d.]+))?"
			}
		},
		"Hinza Advanced CMS": {
			"meta": {
				"generator": [
					"hinzacms"
				]
			},
			"implies": [
				"Laravel"
			]
		},
		"Datadome": {
			"cookies": {
				"datadome": ""
			},
			"headers": {
				"x-datadome-cid": ""
			}
		},
		"Yandex.Direct": {
			"js": [
				"yandex_ad_format",
				"yandex_partner_id"
			],
			"html": [
				"<yatag class=\"ya-partner__ads\">"
			]
		},
		"Envoy": {
			"headers": {
				"server": "^envoy$",
				"x-envoy-upstream-service-time": ""
			}
		},
		"Artifactory": {
			"js": [
				"artifactoryupdates"
			],
			"html": [
				"<span class=\"version\">artifactory(?: pro)?(?: power pack)?(?: ([\\d.]+))?"
			]
		},
		"Web2py": {
			"headers": {
				"x-powered-by": "web2py"
			},
			"meta": {
				"generator": [
					"^web2py"
				]
			},
			"implies": [
				"Python",
				"jQuery"
			]
		},
		"ManyChat": {
			"js": [
				"mcwidget"
			]
		},
		"eWAY Payments": {
			"html": [
				"<img [^>]*src=\"[^\/]*\/\/[^\/]*eway\\.com"
			]
		},
		"F5 BigIP": {
			"cookies": {
				"mrhsession": ""
			},
			"headers": {
				"server": "^big-?ip$"
			}
		},
		"Paddle": {
			"js": [
				"paddle.checkout",
				"paddlescriptlocation"
			]
		},
		"Tilda": {
			"html": [
				"<link[^>]* href=[^>]+tilda(?:cdn|\\.ws|-blocks)"
			]
		},
		"ip-label": {
			"js": [
				"clobs"
			]
		},
		"LEPTON": {
			"meta": {
				"generator": [
					"lepton"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"scrollreveal": {
			"js": [
				"scrollreveal().version"
			],
			"html": [
				"<[^>]+data-sr(?:-id)"
			]
		},
		"Lagoon": {
			"headers": {
				"x-lagoon": ""
			}
		},
		"LocomotiveCMS": {
			"implies": [
				"Ruby on Rails",
				"MongoDB"
			],
			"html": [
				"<link[^>]*\/sites\/[a-z\\d]{24}\/theme\/stylesheets"
			]
		},
		"Advert Stream": {
			"js": [
				"advst_is_above_the_fold"
			]
		},
		"Kemal": {
			"headers": {
				"x-powered-by": "kemal"
			}
		},
		"KineticJS": {
			"js": [
				"kinetic",
				"kinetic.version"
			]
		},
		"Doxygen": {
			"meta": {
				"generator": [
					"doxygen ([\\d.]+)"
				]
			},
			"html": [
				"(?:<!-- generated by doxygen ([\\d.]+)|<link[^>]+doxygen\\.css)"
			]
		},
		"Gatsby": {
			"meta": {
				"generator": [
					"^gatsby(?: ([0-9.]+))?$"
				]
			},
			"html": [
				"<div id=\"___gatsby\">",
				"<style id=\"gatsby-inlined-css\">"
			],
			"implies": [
				"React",
				"webpack"
			]
		},
		"Zoey": {
			"implies": [
				"PHP",
				"MySQL"
			],
			"js": [
				"zoey.module",
				"zoey.developer",
				"zoeydev"
			]
		},
		"mod_fastcgi": {
			"headers": {
				"server": "mod_fastcgi(?:\/([\\d.]+))?"
			},
			"implies": [
				"Apache"
			]
		},
		"Ubuntu": {
			"headers": {
				"server": "ubuntu",
				"x-powered-by": "ubuntu"
			}
		},
		"Pagely": {
			"headers": {
				"server": "^pagely"
			},
			"implies": [
				"WordPress",
				"Amazon Web Services"
			]
		},
		"Crownpeak": {
			"js": [
				"crownpeakautocomplete",
				"crownpeaksearch"
			]
		},
		"MotoCMS": {
			"implies": [
				"PHP",
				"AngularJS",
				"jQuery"
			],
			"html": [
				"<link [^>]*href=\"[^>]*\\\/mt-content\\\/[^>]*\\.css"
			]
		},
		"HubSpot": {
			"js": [
				"_hsq",
				"hubspot"
			],
			"html": [
				"<!-- start of async hubspot"
			]
		},
		"RevLifter": {
			"cookies": {
				"revlifter": ""
			},
			"js": [
				"revlifterobject",
				"revlifter"
			]
		},
		"Firebase": {
			"js": [
				"firebase.sdk_version"
			]
		},
		"Storyblok": {
			"meta": {
				"generator": [
					"storyblok"
				]
			}
		},
		"Etracker": {
			"js": [
				"_etracker"
			]
		},
		"DedeCMS": {
			"implies": [
				"PHP"
			],
			"js": [
				"dedecontainer",
				"dedeajax2"
			],
			"html": [
				"dedecms.com"
			]
		},
		"Albacross": {
			"js": [
				"_nqsv"
			]
		},
		"prettyPhoto": {
			"implies": [
				"jQuery"
			],
			"js": [
				"pp_titles",
				"pp_alreadyinitialized",
				"pp_descriptions",
				"pp_images"
			],
			"html": [
				"(?:<link [^>]*href=\"[^\"]*prettyphoto(?:\\.min)?\\.css|<a [^>]*rel=\"prettyphoto)"
			]
		},
		"Windows CE": {
			"headers": {
				"server": "\\bwince\\b"
			}
		},
		"Ruby": {
			"headers": {
				"server": "(?:mongrel|webrick|ruby)"
			}
		},
		"Google Tag Manager": {
			"js": [
				"googletag",
				"google_tag_manager"
			],
			"html": [
				"googletagmanager\\.com\/ns\\.html[^>]+><\/iframe>",
				"<!-- (?:end )?google tag manager -->"
			]
		},
		"Isotope": {
			"js": [
				"isotope",
				"init_isotope"
			]
		},
		"TagCommander": {
			"js": [
				"tc_vars"
			]
		},
		"Kentico CMS": {
			"cookies": {
				"cmspreferredculture": ""
			},
			"js": [
				"cms.application"
			],
			"meta": {
				"generator": [
					"kentico cms ([\\d.r]+ \\(build [\\d.]+\\))"
				]
			}
		},
		"Emarsys": {
			"js": [
				"scarab",
				"scarabqueue"
			]
		},
		"AngularDart": {
			"implies": [
				"Dart"
			],
			"js": [
				"ngtestabilityregistries"
			]
		},
		"Amazon ECS": {
			"headers": {
				"server": "^ecs"
			},
			"implies": [
				"Amazon Web Services",
				"Docker"
			]
		},
		"Zope": {
			"headers": {
				"server": "^zope\/"
			}
		},
		"AddThis": {
			"js": [
				"addthis"
			]
		},
		"Chamilo": {
			"meta": {
				"generator": [
					"chamilo ([\\d.]+)"
				]
			},
			"headers": {
				"x-powered-by": "chamilo ([\\d.]+)"
			},
			"implies": [
				"PHP"
			],
			"html": [
				"\">chamilo ([\\d.]+)<\/a>"
			]
		},
		"Trac": {
			"implies": [
				"Python"
			],
			"html": [
				"<a id=\"tracpowered",
				"powered by <a href=\"[^\"]*\"><strong>trac(?:[ \/]([\\d.]+))?"
			]
		},
		"Hotjar": {
			"js": [
				"hotleadcontroller",
				"hj.apiurlbase",
				"hotleadfactory"
			]
		},
		"SlickStack": {
			"headers": {
				"x-powered-by": "slickstack"
			},
			"implies": [
				"WordPress"
			]
		},
		"Scorpion": {
			"js": [
				"process.userdata"
			],
			"html": [
				"<[^>]+id=\"hsscorpion"
			]
		},
		"Sqreen": {
			"headers": {
				"x-protected-by": "^sqreen$"
			}
		},
		"HTTP\/2": {
			"headers": {
				"x-firefox-spdy": "h2"
			}
		},
		"Shopatron": {
			"meta": {
				"keywords": [
					"shopatron"
				]
			},
			"js": [
				"shpturl"
			],
			"html": [
				"<body class=\"shopatron",
				"<img[^>]+mediacdn\\.shopatron\\.com"
			]
		},
		"Swiftlet": {
			"meta": {
				"generator": [
					"swiftlet"
				]
			},
			"headers": {
				"x-powered-by": "swiftlet",
				"x-swiftlet-cache": "",
				"x-generator": "swiftlet"
			},
			"implies": [
				"PHP"
			],
			"html": [
				"powered by <a href=\"[^>]+swiftlet"
			]
		},
		"mod_auth_pam": {
			"headers": {
				"server": "mod_auth_pam(?:\/([\\d\\.]+))?"
			},
			"implies": [
				"Apache"
			]
		},
		"Nukeviet CMS": {
			"meta": {
				"generator": [
					"nukeviet v([\\d.]+)"
				]
			},
			"js": [
				"nv_is_change_act_confirm",
				"nv_digitalclock"
			]
		},
		"Robin": {
			"js": [
				"_robin_getrobinjs",
				"robin_settings",
				"robin_storage_settings"
			]
		},
		"Pars Elecom Portal": {
			"headers": {
				"x-powered-by": "pars elecom portal"
			},
			"meta": {
				"copyright": [
					"pars elecom portal"
				]
			},
			"implies": [
				"Microsoft ASP.NET",
				"IIS",
				"Windows Server"
			]
		},
		"Mono.net": {
			"implies": [
				"Matomo Analytics"
			],
			"js": [
				"_monotracker"
			]
		},
		"EmbedThis Appweb": {
			"headers": {
				"server": "mbedthis-appweb(?:\/([\\d.]+))?"
			}
		},
		"Twitter Flight": {
			"implies": [
				"jQuery"
			],
			"js": [
				"flight"
			]
		},
		"WP Rocket": {
			"headers": {
				"x-powered-by": "wp rocket(?:\/([\\d.]+))?",
				"x-rocket-nginx-bypass": ""
			},
			"html": [
				"<!--[^>]+wp rocket"
			],
			"implies": [
				"WordPress"
			]
		},
		"OpenBSD httpd": {
			"headers": {
				"server": "^openbsd httpd"
			}
		},
		"Prediggo": {
			"js": [
				"prediggo",
				"prediggosearchformexternalac"
			]
		},
		"Bronto": {
			"js": [
				"bronto.versions.sca",
				"brontocookieconsent",
				"brontoshopify"
			]
		},
		"VWO": {
			"js": [
				"vwo",
				"__vwo"
			]
		},
		"POWR": {
			"js": [
				"powr_receivers",
				"loadpowr"
			]
		},
		"Booksy": {
			"js": [
				"booksy"
			]
		},
		"Solve Media": {
			"js": [
				"acpuzzle",
				"_acpuzzle",
				"_adcopy-puzzle-image-image",
				"adcopy-puzzle-image-image"
			]
		},
		"Gemius": {
			"js": [
				"gemius_hit",
				"gemius_init",
				"gemius_pending",
				"pp_gemius_hit"
			],
			"html": [
				"<a [^>]*onclick=\"gemius_hit"
			]
		},
		"BoldGrid": {
			"implies": [
				"WordPress"
			],
			"html": [
				"<link rel=[\"']stylesheet[\"'] [^>]+boldgrid",
				"<link rel=[\"']stylesheet[\"'] [^>]+post-and-page-builder",
				"<link[^>]+s\\d+\\.boldgrid\\.com"
			]
		},
		"Etherpad": {
			"headers": {
				"server": "^etherpad"
			},
			"js": [
				"padeditbar",
				"padimpexp"
			],
			"implies": [
				"Node.js"
			]
		},
		"Koobi": {
			"meta": {
				"generator": [
					"koobi"
				]
			},
			"html": [
				"<!--[^k>-]+koobi ([a-z\\d.]+)"
			]
		},
		"Ghost": {
			"headers": {
				"x-ghost-cache-status": ""
			},
			"meta": {
				"generator": [
					"ghost(?:\\s([\\d.]+))?"
				]
			},
			"implies": [
				"Node.js"
			]
		},
		"Impact": {
			"js": [
				"impactradiusevent",
				"irevent"
			]
		},
		"Bookingkit": {
			"js": [
				"bookingkitapp"
			]
		},
		"Smart Ad Server": {
			"js": [
				"smartadserver"
			],
			"html": [
				"<img[^>]+smartadserver\\.com\\\/call"
			]
		},
		"Arc Publishing": {
			"js": [
				"fusion.arcsite"
			],
			"html": [
				"<div [^>]*id=\"pb-root\""
			]
		},
		"Google Charts": {
			"js": [
				"__gvizguard__",
				"__googlevisualizationabstractrendererelementscount__"
			]
		},
		"Google App Engine": {
			"headers": {
				"server": "google frontend"
			}
		},
		"Snap": {
			"headers": {
				"server": "snap\/([.\\d]+)"
			},
			"implies": [
				"Haskell"
			]
		},
		"LiveZilla": {
			"js": [
				"lz_chat_execute",
				"lz_code_id",
				"lz_tracking_set_widget_visibility"
			]
		},
		"Sovrn\/\/Commerce": {
			"js": [
				"vl_disable",
				"vglnk",
				"vl_cb"
			]
		},
		"Kestrel": {
			"headers": {
				"server": "^kestrel"
			},
			"implies": [
				"Microsoft ASP.NET"
			]
		},
		"VideoJS": {
			"js": [
				"videojs",
				"videojs.version",
				"videojs"
			],
			"html": [
				"<div[^>]+class=\"video-js+\">"
			]
		},
		"Skimlinks": {
			"js": [
				"__skim_js_global__",
				"addskimlinks",
				"skimlinksapi"
			]
		},
		"3dCart": {
			"cookies": {
				"3dvisit": ""
			},
			"headers": {
				"x-powered-by": "3dcart"
			}
		},
		"Gitea": {
			"cookies": {
				"i_like_gitea": ""
			},
			"html": [
				"<div class=\"ui left\">\\n\\s+© gitea version: ([\\d.]+)"
			],
			"meta": {
				"keywords": [
					"^go,git,self-hosted,gitea$"
				]
			}
		},
		"Atlassian Bitbucket": {
			"meta": {
				"application-name": [
					"bitbucket"
				]
			},
			"js": [
				"bitbucket"
			],
			"implies": [
				"Python"
			],
			"html": [
				"<li>atlassian bitbucket <span title=\"[a-z0-9]+\" id=\"product-version\" data-commitid=\"[a-z0-9]+\" data-system-build-number=\"[a-z0-9]+\"> v([\\d.]+)<"
			]
		},
		"JW Player": {
			"js": [
				"jwdefaults",
				"jwplayer",
				"jwplayerapiurl",
				"webpackjsonpjwplayer"
			]
		},
		"PHP-Nuke": {
			"meta": {
				"generator": [
					"php-nuke"
				]
			},
			"html": [
				"<[^>]+powered by php-nuke"
			],
			"implies": [
				"PHP"
			]
		},
		"JS Charts": {
			"js": [
				"jschart"
			]
		},
		"Bootstrap": {
			"implies": [
				"jQuery"
			],
			"js": [
				"bootstrap.alert.version",
				"jquery.fn.tooltip.constructor.version"
			],
			"html": [
				"<style>\\s+\/\\*!\\s+\\* bootstrap v(\\d\\.\\d\\.\\d)",
				"<link[^>]* href=[^>]*?bootstrap(?:[^>]*?([0-9a-fa-f]{7,40}|[\\d]+(?:.[\\d]+(?:.[\\d]+)?)?)|)[^>]*?(?:\\.min)?\\.css"
			]
		},
		"Adcash": {
			"js": [
				"ct_nopp",
				"ct_nsuurl",
				"ct_siteunder",
				"ct_tag",
				"suloaded",
				"suurl",
				"ac_bgclick_url"
			]
		},
		"RackCache": {
			"headers": {
				"x-rack-cache": ""
			},
			"implies": [
				"Ruby"
			]
		},
		"Basic": {
			"headers": {
				"www-authenticate": "^basic"
			},
			"html": [
				"<title>401 authorization<\/title>"
			]
		},
		"SiteSpect": {
			"js": [
				"ss",
				"ss_dom_var"
			]
		},
		"Lithium": {
			"cookies": {
				"lithiumvisitor": ""
			},
			"js": [
				"lithium"
			],
			"implies": [
				"PHP"
			],
			"html": [
				" <a [^>]+powered by lithium"
			]
		},
		"gitweb": {
			"meta": {
				"generator": [
					"gitweb(?:\/([\\d.]+\\d))?"
				]
			},
			"html": [
				"<!-- git web interface version ([\\d.]+)?"
			],
			"implies": [
				"Perl",
				"git"
			]
		},
		"Vercel": {
			"headers": {
				"server": "^now$",
				"x-now-trace": ""
			}
		},
		"FilePond": {
			"js": [
				"filepond",
				"filepond.create",
				"filepond.setoptions"
			]
		},
		"Mattermost": {
			"implies": [
				"Go",
				"React"
			],
			"js": [
				"mm_config",
				"mm_current_user_id",
				"mm_license",
				"mm_user"
			],
			"html": [
				"<noscript> to use mattermost, please enable javascript\\. <\/noscript>"
			]
		},
		"WikkaWiki": {
			"meta": {
				"generator": [
					"wikkawiki"
				]
			},
			"html": [
				"powered by <a href=\"[^>]+wikkawiki"
			]
		},
		"AnyClip": {
			"js": [
				"anyclip"
			]
		},
		"Commerce.js": {
			"headers": {
				"x-powered-by": "commerce.js",
				"chec-version": ".*"
			},
			"js": [
				"commercejsspace"
			]
		},
		"Kamva": {
			"meta": {
				"generator": [
					"[ck]amva"
				]
			},
			"js": [
				"kamva"
			]
		},
		"Mint": {
			"js": [
				"mint"
			]
		},
		"Monkey HTTP Server": {
			"headers": {
				"server": "monkey\/?([\\d.]+)?"
			}
		},
		"Pico": {
			"js": [
				"pico"
			]
		},
		"Jahia DX": {
			"html": [
				"<script id=\"staticassetaggregatedjavascrip"
			]
		},
		"Adobe RoboHelp": {
			"meta": {
				"generator": [
					"^adobe robohelp(?: ([\\d]+))?"
				]
			},
			"js": [
				"gbwhproxy",
				"gbwhutil",
				"gbwhver",
				"gbwhlang",
				"gbwhmsg"
			]
		},
		"TiddlyWiki": {
			"meta": {
				"generator": [
					"^tiddlywiki$"
				],
				"copyright": [
					"^tiddlywiki created by jeremy ruston"
				],
				"tiddlywiki-version": [
					"^(.+)$"
				],
				"application-name": [
					"^tiddlywiki$"
				]
			},
			"js": [
				"tiddler"
			],
			"html": [
				"<[^>]*type=[^>]text\\\/vnd\\.tiddlywiki"
			]
		},
		"Transifex": {
			"js": [
				"transifex.live.lib_version"
			]
		},
		"Vue.js": {
			"js": [
				"vue.version"
			],
			"html": [
				"<[^>]+\\sdata-v(?:ue)?-"
			]
		},
		"BrainSINS": {
			"js": [
				"brainsins",
				"brainsinsrecommender",
				"brainsins_token",
				"launchbrainsins"
			]
		},
		"Phabricator": {
			"cookies": {
				"phsid": ""
			},
			"html": [
				"<[^>]+(?:class|id)=\"phabricator-"
			],
			"implies": [
				"PHP"
			]
		},
		"SQL Buddy": {
			"implies": [
				"PHP"
			],
			"html": [
				"(?:<title>sql buddy<\/title>|<[^>]+onclick=\"sidemainclick\\(\"home\\.php)"
			]
		},
		"Omniconvert": {
			"js": [
				"_omni"
			]
		},
		"cgit": {
			"meta": {
				"generator": [
					"^cgit v([\\d.a-z-]+)$"
				]
			},
			"html": [
				"<[^>]+id='cgit'",
				"generated by <a href='http:\/\/git\\.zx2c4\\.com\/cgit\/about\/'>cgit v([\\d.a-z-]+)<\/a>"
			],
			"implies": [
				"git"
			]
		},
		"sNews": {
			"meta": {
				"generator": [
					"snews"
				]
			}
		},
		"Zend": {
			"cookies": {
				"zendserversessid": ""
			},
			"headers": {
				"x-powered-by": "zend(?:server)?(?:[\\s\/]?([0-9.]+))?"
			}
		},
		"Kibo Personalization": {
			"js": [
				"monetatet",
				"baynoteapi",
				"baynotejsversion",
				"monetate",
				"monetateq"
			]
		},
		"Liveinternet": {
			"html": [
				"<script [^>]*>[\\s\\s]*\/\/counter\\.yadro\\.ru\/hit",
				"<!--liveinternet counter-->",
				"<!--\/liveinternet-->",
				"<a href=\"http:\/\/www\\.liveinternet\\.ru\/click\""
			]
		},
		"Phaser": {
			"js": [
				"phaser",
				"phaser.version"
			]
		},
		"Signifyd": {
			"js": [
				"signifyd_global"
			]
		},
		"Service Provider Pro": {
			"cookies": {
				"spp_csrf": "",
				"spp_orderform": ""
			},
			"js": [
				"spporderform"
			],
			"meta": {
				"server": [
					"app.spp.co"
				]
			}
		},
		"Attentive": {
			"js": [
				"attn_email_save",
				"__attentive",
				"__attentive_domain"
			]
		},
		"Accesso": {
			"js": [
				"accesso"
			]
		},
		"Varbase": {
			"meta": {
				"generator": [
					"varbase"
				]
			},
			"implies": [
				"Drupal"
			]
		},
		"X-Cart": {
			"cookies": {
				"xid": "[a-z\\d]{32}(?:;|$)"
			},
			"meta": {
				"generator": [
					"x-cart(?: (\\d+))?"
				]
			},
			"js": [
				"xcart_web_dir",
				"xliteconfig"
			],
			"implies": [
				"PHP"
			],
			"html": [
				"powered by x-cart(?: (\\d+))? <a[^>]+href=\"http:\/\/www\\.x-cart\\.com\/\"[^>]*>",
				"<a[^>]+href=\"[^\"]*(?:\\?|&)xcart_form_id=[a-z\\d]{32}(?:&|$)"
			]
		},
		"Clerk.io": {
			"js": [
				"__clerk_cb_0",
				"__clerk_q"
			]
		},
		"Volusion": {
			"js": [
				"volusion"
			],
			"html": [
				"<link [^>]*href=\"[^\"]*\/vspfiles\/",
				"<body [^>]*data-vn-page-name"
			]
		},
		"Amiro.CMS": {
			"meta": {
				"generator": [
					"amiro"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"Botble CMS": {
			"cookies": {
				"botble_session": ""
			},
			"headers": {
				"cms-version": "^(.+)$"
			},
			"implies": [
				"Laravel"
			]
		},
		"Adyen": {
			"js": [
				"adyen.encrypt.version"
			]
		},
		"Unbounce": {
			"headers": {
				"x-unbounce-pageid": ""
			}
		},
		"Helpscout": {
			"js": [
				"beacon"
			]
		},
		"J2Store": {
			"implies": [
				"Joomla"
			],
			"js": [
				"j2storeurl"
			]
		},
		"Nosto": {
			"meta": {
				"nosto-version": [
					"([\\d.]+)"
				]
			},
			"js": [
				"nosto",
				"nostojs"
			]
		},
		"Jimdo": {
			"headers": {
				"x-jimdo-instance": ""
			}
		},
		"Liquid Web": {
			"headers": {
				"x-lw-cache": ""
			}
		},
		"Catberry.js": {
			"headers": {
				"x-powered-by": "catberry"
			},
			"js": [
				"catberry",
				"catberry.version"
			],
			"implies": [
				"Node.js"
			]
		},
		"Revel": {
			"cookies": {
				"revel_flash": ""
			},
			"implies": [
				"Go"
			]
		},
		"Telescope": {
			"implies": [
				"Meteor",
				"React"
			],
			"js": [
				"telescope"
			]
		},
		"Microsoft Excel": {
			"meta": {
				"generator": [
					"microsoft excel( [\\d.]+)?"
				],
				"progid": [
					"^excel\\."
				]
			},
			"html": [
				"(?:<html [^>]*xmlns:w=\"urn:schemas-microsoft-com:office:excel\"|<!--\\s*(?:start|end) of output from excel publish as web page wizard\\s*-->|<div [^>]*x:publishsource=\"?excel\"?)"
			]
		},
		"Open Classifieds": {
			"meta": {
				"copyright": [
					"open classifieds ?([0-9.]+)?"
				],
				"author": [
					"open-classifieds\\.com"
				]
			}
		},
		"Fusion Ads": {
			"js": [
				"_fusion"
			]
		},
		"Kount": {
			"js": [
				"ka.clientsdk",
				"ka.collectdata"
			]
		},
		"Virtuoso": {
			"headers": {
				"server": "virtuoso\/?([0-9.]+)?"
			},
			"meta": {
				"copyright": [
					"^copyright &copy; \\d{4} openlink software"
				],
				"keywords": [
					"^openlink virtuoso sparql"
				]
			}
		},
		"Drupal Commerce": {
			"implies": [
				"Drupal"
			],
			"html": [
				"<[^>]+(?:id=\"block[_-]commerce[_-]cart[_-]cart|class=\"commerce[_-]product[_-]field)"
			]
		},
		"Algolia": {
			"js": [
				"algoliasearch.version",
				"algoliasearch",
				"__algolia"
			]
		},
		"Kubernetes Dashboard": {
			"html": [
				"<html ng-app=\"kubernetesdashboard\">"
			]
		},
		"InfernoJS": {
			"js": [
				"inferno",
				"inferno.version"
			]
		},
		"Loja Mestre": {
			"meta": {
				"webmaster": [
					"www\\.lojamestre\\.\\w+\\.br"
				]
			}
		},
		"Modernizr": {
			"js": [
				"modernizr._version"
			]
		},
		"Adminer": {
			"implies": [
				"PHP"
			],
			"html": [
				"adminer<\/a> <span class=\"version\">([\\d.]+)<\/span>",
				"onclick=\"bodyclick\\(event\\);\" onload=\"verifyversion\\('([\\d.]+)'\\);\">"
			]
		},
		"Koa": {
			"headers": {
				"x-powered-by": "^koa$"
			},
			"implies": [
				"Node.js"
			]
		},
		"Cafe24": {
			"js": [
				"ec_global_datetime",
				"ec_global_info",
				"ec_root_domain"
			]
		},
		"Wix": {
			"cookies": {
				"domain": "\\.wix\\.com"
			},
			"meta": {
				"generator": [
					"wix\\.com website builder"
				]
			},
			"js": [
				"wixbisession"
			],
			"headers": {
				"x-wix-renderer-server": ""
			},
			"implies": [
				"React"
			]
		},
		"Hotaru CMS": {
			"cookies": {
				"hotaru_mobile": ""
			},
			"meta": {
				"generator": [
					"hotaru cms"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"Google Sign-in": {
			"html": [
				"<meta[^>]*google-signin-client_id",
				"<meta[^>]*google-signin-scope",
				"<iframe[^>]*accounts\\.google\\.com\/o\/oauth2",
				"<a[^>]*accounts\\.google\\.com\/o\/oauth2"
			]
		},
		"Loja Integrada": {
			"headers": {
				"x-powered-by": "vtex-integrated-store"
			},
			"js": [
				"loja_id"
			]
		},
		"CoinHive Captcha": {
			"html": [
				"(?:<div[^>]+class=\"coinhive-captcha[^>]+data-key|<div[^>]+data-key[^>]+class=\"coinhive-captcha)"
			]
		},
		"Sotel": {
			"meta": {
				"generator": [
					"sotel"
				]
			}
		},
		"Perl": {
			"headers": {
				"server": "\\bperl\\b(?: ?\/?v?([\\d.]+))?"
			}
		},
		"Joomla": {
			"meta": {
				"generator": [
					"joomla!(?: ([\\d.]+))?"
				]
			},
			"js": [
				"jcomments",
				"joomla"
			],
			"headers": {
				"x-content-encoded-by": "joomla! ([\\d.]+)"
			},
			"html": [
				"(?:<div[^>]+id=\"wrapper_r\"|<(?:link|script)[^>]+(?:feed|components)\/com_|<table[^>]+class=\"pill)"
			],
			"implies": [
				"PHP"
			]
		},
		"TikTok Pixel": {
			"js": [
				"tiktokanalyticsobject"
			]
		},
		"Includable": {
			"headers": {
				"x-includable-version": ""
			}
		},
		"Kendo UI": {
			"implies": [
				"jQuery"
			],
			"js": [
				"kendo.version",
				"kendo"
			],
			"html": [
				"<link[^>]*\\s+href=[^>]*styles\/kendo\\.common(?:\\.min)?\\.css[^>]*\/>"
			]
		},
		"Apache JSPWiki": {
			"implies": [
				"Apache Tomcat"
			],
			"html": [
				"<html[^>]* xmlns:jspwiki="
			]
		},
		"Heroku": {
			"headers": {
				"via": "[\\d.-]+ vegur$"
			}
		},
		"ShellInABox": {
			"js": [
				"shellinabox"
			],
			"html": [
				"<title>shell in a box<\/title>",
				"must be enabled for shellinabox<\/noscript>"
			]
		},
		"Kajabi": {
			"cookies": {
				"_kjb_session": ""
			},
			"js": [
				"kajabi"
			]
		},
		"Fat-Free Framework": {
			"headers": {
				"x-powered-by": "^fat-free framework$"
			},
			"implies": [
				"PHP"
			]
		},
		"Kameleoon": {
			"cookies": {
				"kameleoonvisitorcode": ""
			},
			"js": [
				"kameleoonendloadtime",
				"kameleoons",
				"kameleoon.gatherer.script_version"
			]
		},
		"UserLike": {
			"js": [
				"userlike",
				"userlikeinit"
			]
		},
		"Facebook Login": {
			"js": [
				"fb.getloginstatus"
			]
		},
		"Statically": {
			"headers": {
				"server": "^statically$"
			},
			"html": [
				"<link [^>]*?href=\"?[a-z]*?:?\/\/cdn\\.statically\\.io\/"
			]
		},
		"mod_jk": {
			"headers": {
				"server": "mod_jk(?:\/([\\d\\.]+))?"
			},
			"implies": [
				"Apache Tomcat",
				"Apache"
			]
		},
		"Dart": {
			"implies": [
				"AngularDart"
			],
			"js": [
				"___dart__$dart_dartobject_zxyxx_0_",
				"___dart_dispatch_record_zxyxx_0_"
			],
			"html": [
				"\/(?:<script)[^>]+(?:type=\"application\/dart\")\/"
			]
		},
		"Orchard CMS": {
			"meta": {
				"generator": [
					"orchard"
				]
			},
			"implies": [
				"Microsoft ASP.NET"
			]
		},
		"STUDIO": {
			"meta": {
				"generator": [
					"^studio$"
				]
			},
			"implies": [
				"Vue.js",
				"Nuxt.js",
				"Firebase",
				"Google Cloud",
				"Google Tag Manager"
			]
		},
		"Prebid": {
			"js": [
				"prebid_timeout",
				"pbjs"
			]
		},
		"Cleverbridge": {
			"js": [
				"cbcartproductselection"
			]
		},
		"Coppermine": {
			"implies": [
				"PHP"
			],
			"html": [
				"<!--coppermine photo gallery ([\\d.]+)"
			]
		},
		"KISSmetrics": {
			"js": [
				"km_cookie_domain"
			]
		},
		"Artifactory Web Server": {
			"headers": {
				"server": "artifactory(?:\/([\\d.]+))?"
			},
			"implies": [
				"Artifactory"
			]
		},
		"Trustpilot": {
			"js": [
				"trustpilot"
			]
		},
		"Outlook Web App": {
			"implies": [
				"Microsoft ASP.NET",
				"Exchange"
			],
			"js": [
				"isowapremiumbrowser"
			],
			"html": [
				"<link\\s[^>]*href=\"[^\"]*?([\\d.]+)\/themes\/resources\/owafont\\.css",
				"\/owa/auth\/"
			]
		},
		"Sellingo": {
			"js": [
				"sellingoquantitycalc"
			]
		},
		"Swiftype": {
			"js": [
				"swiftype"
			]
		},
		"Omise": {
			"js": [
				"omisecard",
				"omise"
			]
		},
		"Inspectlet": {
			"js": [
				"__insp",
				"__inspld"
			],
			"html": [
				"<!-- (?:begin|end) inspectlet embed code -->"
			]
		},
		"RxJS": {
			"js": [
				"rx.compositedisposable",
				"rx.symbol"
			]
		},
		"Login with Amazon": {
			"js": [
				"onamazonloginready"
			]
		},
		"CrossBox": {
			"headers": {
				"server": "cbx-ws"
			}
		},
		"Lua": {
			"headers": {
				"x-powered-by": "\\blua(?: ([\\d.]+))?"
			}
		},
		"hantana": {
			"js": [
				"hantana"
			]
		},
		"Open Web Analytics": {
			"js": [
				"owa.config.baseurl",
				"owa_baseurl",
				"owa_cmds"
			],
			"html": [
				"<!-- (?:start|end) open web analytics tracker -->"
			]
		},
		"AdRiver": {
			"js": [
				"adriver"
			],
			"html": [
				"(?:<embed[^>]+(?:src=\"https?:\/\/mh\\d?\\.adriver\\.ru\/|flashvars=\"[^\"]*(?:http:%3a\/\/(?:ad|mh\\d?)\\.adriver\\.ru\/|adriver_banner))|<(?:(?:iframe|img)[^>]+src|a[^>]+href)=\"https?:\/\/ad\\.adriver\\.ru\/)"
			]
		},
		"Litespeed Cache": {
			"headers": {
				"x-litespeed-cache": ""
			},
			"implies": [
				"LiteSpeed"
			]
		},
		"Fat Zebra": {
			"html": [
				"<(?:iframe|img|form)[^>]+paynow\\.pmnts\\.io",
				"<(?:iframe)[^>]+fatzebraframe"
			]
		},
		"WHMCS": {
			"js": [
				"whmcs"
			]
		},
		"XOOPS": {
			"meta": {
				"generator": [
					"xoops"
				]
			},
			"js": [
				"xoops"
			],
			"implies": [
				"PHP"
			]
		},
		"Plyr": {
			"js": [
				"plyr"
			]
		},
		"SDL Tridion": {
			"html": [
				"<img[^>]+_tcm\\d{2,3}-\\d{6}\\."
			]
		},
		"Base": {
			"meta": {
				"base-theme-name": [
					"\\d+"
				]
			},
			"js": [
				"base.app.open_nav"
			]
		},
		"Knockout.js": {
			"js": [
				"ko.version"
			]
		},
		"ArvanCloud": {
			"headers": {
				"ar-poweredby": "arvan cloud \\(arvancloud\\.com\\)"
			},
			"js": [
				"arvancloud"
			]
		},
		"SoundManager": {
			"js": [
				"baconplayer",
				"soundmanager",
				"soundmanager.version"
			]
		},
		"Tumblr": {
			"headers": {
				"x-tumblr-user": ""
			},
			"html": [
				"<iframe src=\"[^>]+tumblr\\.com"
			]
		},
		"Listrak": {
			"js": [
				"_ltksubscriber",
				"_ltksignup"
			]
		},
		"Post Affiliate Pro": {
			"js": [
				"postaffcookie",
				"postaffinfo",
				"postafftracker",
				"postaffaction"
			]
		},
		"Comandia": {
			"js": [
				"comandia"
			],
			"html": [
				"<link[^>]+=['\"]\/\/cdn\\.mycomandia\\.com"
			]
		},
		"SublimeVideo": {
			"js": [
				"sublimevideo"
			]
		},
		"Odoo": {
			"meta": {
				"generator": [
					"odoo"
				]
			},
			"html": [
				"<link[^>]* href=[^>]+\/web\/css\/(?:web\\.assets_common\/|website\\.assets_frontend\/)"
			],
			"implies": [
				"Python",
				"PostgreSQL",
				"Node.js",
				"Less"
			]
		},
		"Webix": {
			"js": [
				"webix"
			]
		},
		"Yaws": {
			"headers": {
				"server": "yaws(?: ([\\d.]+))?"
			}
		},
		"Forter": {
			"cookies": {
				"fortertoken": ""
			},
			"js": [
				"window.ftr__startscriptload"
			]
		},
		"Atlassian Jira": {
			"meta": {
				"application-name": [
					"jira"
				],
				"data-version": [
					"([\\d.]+)"
				]
			},
			"js": [
				"jira.id"
			],
			"implies": [
				"Java",
				"Jira"
			]
		},
		"WPCacheOn": {
			"headers": {
				"x-powered-by": "^optimized by wpcacheon"
			},
			"implies": [
				"WordPress"
			]
		},
		"UIKit": {
			"html": [
				"<[^>]+class=\"[^\"]*(?:uk-container|uk-section)"
			]
		},
		"UltraCart": {
			"js": [
				"uccatalog"
			],
			"html": [
				"<form [^>]*action=\"[^\"]*\\\/cgi-bin\\\/uceditor\\?(?:[^\"]*&)?merchantid=[^\"]"
			]
		},
		"Cowboy": {
			"headers": {
				"server": "^cowboy$"
			}
		},
		"Taboola": {
			"js": [
				"_taboolanetworkmode",
				"taboola_view_id",
				"_taboola"
			]
		},
		"Rickshaw": {
			"implies": [
				"D3"
			],
			"js": [
				"rickshaw"
			]
		},
		"Sanity": {
			"headers": {
				"x-sanity-shard": ""
			}
		},
		"LiveAgent": {
			"js": [
				"liveagent"
			]
		},
		"Quick.CMS": {
			"meta": {
				"generator": [
					"quick\\.cms(?: v([\\d.]+))?"
				]
			},
			"html": [
				"<a href=\"[^>]+opensolution\\.org\/\">cms by"
			]
		},
		"CentOS": {
			"headers": {
				"server": "centos",
				"x-powered-by": "centos"
			}
		},
		"SunOS": {
			"headers": {
				"server": "sunos( [\\d\\.]+)?",
				"servlet-engine": "sunos( [\\d\\.]+)?"
			}
		},
		"Open AdStream": {
			"js": [
				"oas_ad"
			]
		},
		"Umbraco": {
			"meta": {
				"generator": [
					"umbraco"
				]
			},
			"js": [
				"uc_item_info_service",
				"uc_settings",
				"umbraco",
				"uc_image_service|item_info_service"
			],
			"headers": {
				"x-umbraco-version": "^(.+)$"
			},
			"html": [
				"powered by <a href=[^>]+umbraco"
			],
			"implies": [
				"Microsoft ASP.NET"
			]
		},
		"VWO Engage": {
			"js": [
				"_pushcrewdebuggingqueue"
			]
		},
		"Semantic UI": {
			"html": [
				"<link[^>]+semantic(?:\\.min)\\.css\""
			]
		},
		"Snap.svg": {
			"js": [
				"snap.version"
			]
		},
		"Usabilla": {
			"js": [
				"usabilla_live"
			]
		},
		"Rayo": {
			"meta": {
				"generator": [
					"^rayo"
				]
			},
			"js": [
				"rayo"
			],
			"implies": [
				"AngularJS",
				"Microsoft ASP.NET"
			]
		},
		"Raspbian": {
			"headers": {
				"server": "raspbian",
				"x-powered-by": "raspbian"
			}
		},
		"Boomerang": {
			"js": [
				"boomr",
				"boomr_lstart",
				"boomr_mq"
			]
		},
		"Saber": {
			"meta": {
				"generator": [
					"^saber v([\\d.]+)$"
				]
			},
			"html": [
				"<div [^>]*id=\"_saber\""
			],
			"implies": [
				"Vue.js"
			]
		},
		"Eleanor CMS": {
			"meta": {
				"generator": [
					"eleanor"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"CPG Dragonfly": {
			"headers": {
				"x-powered-by": "^dragonfly cms"
			},
			"meta": {
				"generator": [
					"cpg dragonfly"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"Windows Server": {
			"headers": {
				"server": "win32|win64"
			}
		},
		"Yepcomm": {
			"meta": {
				"copyright": [
					"yepcomm tecnologia"
				],
				"author": [
					"yepcomm tecnologia"
				]
			}
		},
		"Vignette": {
			"html": [
				"<[^>]+=\"vgn-?ext"
			]
		},
		"Octopress": {
			"meta": {
				"generator": [
					"octopress"
				]
			},
			"html": [
				"powered by <a href=\"http:\/\/octopress\\.org\">"
			],
			"implies": [
				"Jekyll"
			]
		},
		"Express": {
			"headers": {
				"x-powered-by": "^express$"
			},
			"implies": [
				"Node.js"
			]
		},
		"FAST ESP": {
			"html": [
				"<form[^>]+id=\"fastsearch\""
			]
		},
		"Marketo": {
			"js": [
				"munchkin"
			]
		},
		"Exhibit": {
			"js": [
				"exhibit.version",
				"exhibit"
			]
		},
		"Vuetify": {
			"css": [
				"\\.v-application \\.d-block "
			],
			"html": [
				"<div data-app[^>]+class=\"v-application"
			],
			"implies": [
				"Vue.js"
			]
		},
		"Mobify": {
			"headers": {
				"x-powered-by": "mobify"
			},
			"js": [
				"mobify"
			]
		},
		"ReDoc": {
			"implies": [
				"React"
			],
			"js": [
				"redoc.version"
			],
			"html": [
				"<redoc "
			]
		},
		"Okendo": {
			"js": [
				"okereviewswidgetoninit",
				"okewidgetcontrolinit",
				"okendoreviews"
			]
		},
		"Snoobi": {
			"js": [
				"snoobi"
			]
		},
		"Instana": {
			"js": [
				"ineum"
			]
		},
		"Blesta": {
			"cookies": {
				"blesta_sid": ""
			}
		},
		"Shopify": {
			"cookies": {
				"_shopify_s": ""
			},
			"meta": {
				"shopify-digital-wallet": [

				],
				"shopify-checkout-api-token": [

				]
			},
			"js": [
				"shopify",
				"shopifyapi"
			],
			"headers": {
				"x-shopify-stage": "",
				"x-shopid": ""
			}
		},
		"Flywheel": {
			"headers": {
				"x-fw-static": "",
				"x-fw-server": "^flywheel(?:\/([\\d.]+))?"
			},
			"implies": [
				"WordPress"
			]
		},
		"Discourse": {
			"meta": {
				"generator": [
					"discourse(?: ?\/?([\\d.]+\\d))?"
				]
			},
			"js": [
				"discourse"
			],
			"implies": [
				"Ruby on Rails"
			]
		},
		"AdOcean": {
			"implies": [
				"Gemius"
			],
			"js": [
				"ado.slave",
				"ado.master",
				"ado.placement"
			]
		},
		"Marketo Forms": {
			"js": [
				"formatmarketoform"
			]
		},
		"All in One SEO Pack": {
			"implies": [
				"WordPress"
			],
			"html": [
				"<!-- all in one seo pack ([\\d.]+) "
			]
		},
		"JavaScript Infovis Toolkit": {
			"js": [
				"$jit",
				"$jit.version"
			]
		},
		"Microsoft SharePoint": {
			"headers": {
				"sprequestguid": "",
				"microsoftsharepointteamservices": "^(.+)$"
			},
			"js": [
				"spdesignerprogid",
				"_spbodyonloadcalled"
			],
			"meta": {
				"generator": [
					"microsoft sharepoint"
				]
			}
		},
		"Day.js": {
			"js": [
				"dayjs"
			]
		},
		"PerimeterX": {
			"cookies": {
				"_px3": ""
			}
		},
		"1C-Bitrix": {
			"headers": {
				"x-powered-cms": "bitrix site manager",
				"set-cookie": "bitrix_"
			},
			"html": [
				"(?:<link[^>]+components\/bitrix|(?:src|href)=\"\/bitrix\/(?:js|templates))"
			],
			"implies": [
				"PHP"
			]
		},
		"Optimizely": {
			"js": [
				"optimizely"
			]
		},
		"NextGEN Gallery": {
			"implies": [
				"WordPress"
			],
			"html": [
				"<!-- <meta name=\"nextgen\" version=\"([\\d.]+)\" \/> -->"
			]
		},
		"Avangate": {
			"js": [
				"__avng8_",
				"avng8_"
			],
			"html": [
				"<link[^>]* href=\"https?:\/\/edge\\.avangate\\.net\/"
			]
		},
		"Sailthru": {
			"cookies": {
				"sailthru_pageviews": ""
			},
			"js": [
				"sailthru",
				"sailthruidentify",
				"sailthrunewsletterregistration",
				"tracksailthruuser"
			],
			"meta": {
				"sailthru.title": [

				],
				"sailthru.image.full": [

				]
			}
		},
		"GetSocial": {
			"js": [
				"getsocial_version"
			]
		},
		"EX.CO": {
			"js": [
				"__exco",
				"__exco_integration_type",
				"excopixelurl"
			]
		},
		"ShinyStat": {
			"js": [
				"sssdk"
			],
			"html": [
				"<img[^>]*\\s+src=['\"]?https?:\/\/www\\.shinystat\\.com\/cgi-bin\/shinystat\\.cgi\\?[^'\"\\s>]*['\"\\s\/>]"
			]
		},
		"DM Polopoly": {
			"implies": [
				"Java"
			],
			"html": [
				"<(?:link [^>]*href|img [^>]*src)=\"\/polopoly_fs\/"
			]
		},
		"OpenNemas": {
			"headers": {
				"x-powered-by": "opennemas"
			},
			"meta": {
				"generator": [
					"opennemas"
				]
			}
		},
		"AquilaCMS": {
			"meta": {
				"powered-by": [
					"aquilacms"
				]
			},
			"implies": [
				"Next.js",
				"Node.js",
				"React",
				"MongoDB",
				"Amazon Web Services"
			]
		},
		"Shoper": {
			"js": [
				"shoper"
			]
		},
		"Subrion": {
			"headers": {
				"x-powered-cms": "subrion cms"
			},
			"meta": {
				"generator": [
					"^subrion "
				]
			},
			"implies": [
				"PHP"
			]
		},
		"Sitecore": {
			"cookies": {
				"sc_analytics_global_cookie": ""
			},
			"html": [
				"<img[^>]+src=\"[^>]*\/~\/media\/[^>]+\\.ashx"
			]
		},
		"Craft Commerce": {
			"headers": {
				"x-powered-by": "\\bcraft commerce\\b"
			},
			"implies": [
				"Craft CMS"
			]
		},
		"Calendly": {
			"js": [
				"calendly"
			]
		},
		"MailChimp": {
			"js": [
				"mc4wp"
			],
			"html": [
				"<form [^>]*data-mailchimp-url",
				"<form [^>]*id=\"mc-embedded-subscribe-form\"",
				"<form [^>]*name=\"mc-embedded-subscribe-form\"",
				"<input [^>]*id=\"mc-email\"",
				"<!-- begin mailchimp signup form -->"
			]
		},
		"Yandex.Metrika": {
			"js": [
				"yandex_metrika"
			]
		},
		"Lotus Domino": {
			"headers": {
				"server": "lotus-domino"
			},
			"implies": [
				"Java"
			]
		},
		"Akamai mPulse": {
			"cookies": {
				"akaas_ab-testing": ""
			},
			"js": [
				"boomr_api_key"
			],
			"implies": [
				"Boomerang"
			],
			"html": [
				"<script>[\\s\\s]*?go-mpulse\\.net\\\/boomerang[\\s\\s]*?<\/script>"
			]
		},
		"Serendipity": {
			"meta": {
				"generator": [
					"serendipity(?: v\\.([\\d.]+))?"
				],
				"powered-by": [
					"serendipity v\\.([\\d.]+)"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"OpenX": {
			"js": [
				"openx.name"
			]
		},
		"Resy": {
			"js": [
				"resywidget"
			]
		},
		"Dynatrace": {
			"cookies": {
				"dtcookie1": ""
			},
			"js": [
				"dtrum"
			]
		},
		"Neos Flow": {
			"headers": {
				"x-flow-powered": "flow\/?(.+)?$"
			},
			"implies": [
				"PHP"
			]
		},
		"GOV.UK Toolkit": {
			"js": [
				"govuk.details",
				"govuk.modules",
				"govuk.primarylinks"
			]
		},
		"Occasion": {
			"js": [
				"occsn.stack",
				"occsnmerchanttoken"
			]
		},
		"PayPal": {
			"js": [
				"paypal",
				"enablepaypal",
				"paypalclientid",
				"paypaljs"
			],
			"html": [
				"<input[^>]+_s-xclick"
			]
		},
		"AngularJS": {
			"js": [
				"angular",
				"angular.version.full"
			],
			"html": [
				"<(?:div|html)[^>]+ng-app=",
				"<ng-app"
			]
		},
		"Methode": {
			"meta": {
				"eomportal-uuid": [
					"[a-f\\d]+"
				],
				"eomportal-lastupdate": [

				],
				"eomportal-loid": [
					"[\\d.]+"
				],
				"eomportal-id": [
					"\\d+"
				],
				"eomportal-instanceid": [
					"\\d+"
				]
			},
			"html": [
				"<!-- methode uuid: \"[a-f\\d]+\" ?-->"
			]
		},
		"Mastercard": {
			"html": [
				"<[^>]+aria-labelledby=\"pi-mastercard"
			]
		},
		"PHPDebugBar": {
			"js": [
				"phpdebugbar",
				"phpdebugbar"
			]
		},
		"Project Wonderful": {
			"js": [
				"pw_adloader"
			],
			"html": [
				"<div[^>]+id=\"pw_adbox_"
			]
		},
		"SnapEngage": {
			"js": [
				"snapengage",
				"snapengagechat",
				"snapengage_mobile"
			],
			"html": [
				"<!-- begin snapengage"
			]
		},
		"Yii": {
			"cookies": {
				"yii_csrf_token": ""
			},
			"html": [
				"powered by <a href=\"http:\/\/www\\.yiiframework\\.com\/\" rel=\"external\">yii framework<\/a>",
				"<input type=\"hidden\" value=\"[a-za-z0-9]{40}\" name=\"yii_csrf_token\" \\\/>",
				"<!\\[cdata\\[yii-block-(?:head|body-begin|body-end)\\]"
			],
			"implies": [
				"PHP"
			]
		},
		"GlassFish": {
			"headers": {
				"server": "glassfish(?: server)?(?: open source edition)?(?: ?\/?([\\d.]+))?"
			},
			"implies": [
				"Java"
			]
		},
		"MadAdsMedia": {
			"js": [
				"setmiframe",
				"setmrefurl"
			]
		},
		"A-Frame": {
			"implies": [
				"three.js"
			],
			"js": [
				"aframe.version"
			],
			"html": [
				"<a-scene[^<>]*>"
			]
		},
		"VIVVO": {
			"cookies": {
				"vivvosessionid": ""
			},
			"js": [
				"vivvo"
			]
		},
		"ClickTale": {
			"js": [
				"clicktaleevent",
				"clicktaleglobal",
				"clicktalestarteventsignal",
				"clicktale"
			]
		},
		"Misskey": {
			"meta": {
				"application-name": [
					"misskey"
				]
			},
			"html": [
				"<!-- thank you for using misskey! @syuilo -->"
			]
		},
		"Amazon Cloudfront": {
			"headers": {
				"via": "\\(cloudfront\\)$",
				"x-amz-cf-id": ""
			},
			"implies": [
				"Amazon Web Services"
			]
		},
		"Powergap": {
			"html": [
				"<a[^>]+title=\"powergap",
				"<input type=\"hidden\" name=\"shopid\""
			]
		},
		"Cloudflare Browser Insights": {
			"js": [
				"__cfbeaconcustomtag"
			]
		},
		"Bluefish": {
			"meta": {
				"generator": [
					"bluefish(?:\\s([\\d.]+))?"
				]
			}
		},
		"Oxatis": {
			"meta": {
				"generator": [
					"^oxatis\\s\\(www\\.oxatis\\.com\\)$"
				]
			}
		},
		"EPrints": {
			"meta": {
				"generator": [
					"eprints ([\\d.]+)"
				]
			},
			"js": [
				"eprints",
				"epjs_menu_template"
			],
			"implies": [
				"Perl"
			]
		},
		"UpSellit": {
			"js": [
				"usi_analytics",
				"usi_app",
				"usi_commons",
				"usi_cookies"
			]
		},
		"Bootstrap Table": {
			"implies": [
				"Bootstrap",
				"jQuery"
			],
			"html": [
				"<link[^>]+href=\"[^>]*bootstrap-table(?:\\.min)?\\.css"
			]
		},
		"xCharts": {
			"implies": [
				"D3"
			],
			"js": [
				"xchart"
			],
			"html": [
				"<link[^>]* href=\"[^\"]*xcharts(?:\\.min)?\\.css"
			]
		},
		"EasyEngine": {
			"headers": {
				"x-powered-by": "^easyengine (.*)$"
			},
			"implies": [
				"Docker"
			]
		},
		"Marked": {
			"js": [
				"marked"
			]
		},
		"Slimbox": {
			"implies": [
				"MooTools"
			],
			"html": [
				"<link [^>]*href=\"[^\/]*slimbox(?:-rtl)?\\.css"
			]
		},
		"Fork CMS": {
			"meta": {
				"generator": [
					"^fork cms$"
				]
			},
			"implies": [
				"Symfony"
			]
		},
		"Moodle": {
			"cookies": {
				"moodleid_": ""
			},
			"meta": {
				"keywords": [
					"^moodle"
				]
			},
			"js": [
				"m.core",
				"y.moodle"
			],
			"implies": [
				"PHP"
			],
			"html": [
				"<img[^>]+moodlelogo"
			]
		},
		"MyLiveChat": {
			"js": [
				"mylivechat.version"
			]
		},
		"Oracle HTTP Server": {
			"headers": {
				"server": "oracle-http-server(?:\/([\\d.]+))?"
			}
		},
		"Optimise": {
			"js": [
				"omid"
			]
		},
		"Whatfix": {
			"js": [
				"_wfx_add_logger",
				"_wfx_settings",
				"wfx_is_playing__"
			]
		},
		"AdRoll": {
			"js": [
				"adroll_adv_id",
				"adroll_pix_id"
			]
		},
		"emBlue": {
			"js": [
				"emblueonsiteapp"
			]
		},
		"OpenCart": {
			"cookies": {
				"ocsessid": ""
			},
			"implies": [
				"PHP"
			]
		},
		"PeerTube": {
			"meta": {
				"og:platform": [
					"^peertube$"
				]
			}
		},
		"TomatoCart": {
			"meta": {
				"generator": [
					"tomatocart"
				]
			},
			"js": [
				"ajaxshoppingcart"
			]
		},
		"Fastcommerce": {
			"meta": {
				"generator": [
					"^fastcommerce"
				]
			}
		},
		"WP Engine": {
			"headers": {
				"x-pass-why": ""
			},
			"implies": [
				"WordPress"
			]
		},
		"XpressEngine": {
			"meta": {
				"generator": [
					"xpressengine"
				]
			}
		},
		"GoCache": {
			"headers": {
				"server": "^gocache$",
				"x-gocache-cachestatus": ""
			}
		},
		"D3": {
			"js": [
				"d3.version"
			]
		},
		"RainLoop": {
			"meta": {
				"rlappversion": [
					"^([0-9.]+)$"
				]
			},
			"js": [
				"rainloop",
				"rainloopi18n"
			],
			"headers": {
				"server": "^rainloop"
			},
			"html": [
				"<link[^>]href=\"rainloop\/v\/([0-9.]+)\/static\/apple-touch-icon\\.png\/>"
			],
			"implies": [
				"PHP"
			]
		},
		"Advanced Web Stats": {
			"implies": [
				"Java"
			],
			"html": [
				"aws\\.src = [^<]+caphyon-analytics"
			]
		},
		"DTG": {
			"implies": [
				"Mono.net"
			],
			"html": [
				"<a[^>]+site powered by dtg"
			]
		},
		"Melis Platform": {
			"meta": {
				"generator": [
					"^melis platform\\."
				],
				"powered-by": [
					"^melis cms\\."
				]
			},
			"html": [
				"<!-- rendered with melis cms v2",
				"<!-- rendered with melis platform"
			],
			"implies": [
				"Apache",
				"PHP",
				"MySQL",
				"Symfony",
				"Laravel",
				"Zend"
			]
		},
		"Elm": {
			"js": [
				"elm.main.embed",
				"elm.main.init"
			]
		},
		"Green Valley CMS": {
			"meta": {
				"dc.identifier": [
					"\/content\\.jsp\\?objectid="
				]
			},
			"html": [
				"<img[^>]+\/dsresource\\?objectid="
			],
			"implies": [
				"Apache Tomcat"
			]
		},
		"Broadstreet": {
			"js": [
				"broadstreet"
			]
		},
		"Mastodon": {
			"cookies": {
				"_mastodon_session": ""
			},
			"headers": {
				"server": "^mastodon$"
			}
		},
		"Live Story": {
			"js": [
				"lshelpers",
				"livestory"
			]
		},
		"Javadoc": {
			"html": [
				"<!-- generated by javadoc -->"
			]
		},
		"PHP": {
			"cookies": {
				"phpsessid": ""
			},
			"headers": {
				"server": "php\/?([\\d.]+)?",
				"x-powered-by": "^php\/?([\\d.]+)?"
			}
		},
		"Yoast SEO": {
			"html": [
				"<!-- this site is optimized with the yoast (?:wordpress )?seo plugin v([\\d.]+) -"
			]
		},
		"SPDY": {
			"headers": {
				"x-firefox-spdy": "\\d\\.\\d"
			}
		},
		"YaBB": {
			"html": [
				"powered by <a href=\"[^>]+yabbforum"
			]
		},
		"Oxygen": {
			"implies": [
				"WordPress"
			],
			"html": [
				"<body class=(?:\"|')[^\"']*oxygen-body",
				"<link [^>]*href=(?:\"|')[^>]*wp-content\/plugins\/oxygen\/"
			]
		},
		"Webtrends": {
			"js": [
				"wtoptimize",
				"webtrends"
			],
			"html": [
				"<img[^>]+id=\"dcsimg\"[^>]+webtrends"
			]
		},
		"ShareThis": {
			"js": [
				"sharethis"
			]
		},
		"ExtJS": {
			"js": [
				"ext",
				"ext.version",
				"ext.versions.extjs.version"
			]
		},
		"SPNEGO": {
			"headers": {
				"www-authenticate": "^negotiate"
			}
		},
		"Starhost": {
			"headers": {
				"cache-control": "starhost",
				"x-starhost": ""
			}
		},
		"Wunderkind": {
			"js": [
				"bouncex"
			]
		},
		"Mustache": {
			"js": [
				"mustache.version"
			]
		},
		"Section.io": {
			"headers": {
				"section-io-id": ""
			}
		},
		"Shopware": {
			"meta": {
				"application-name": [
					"shopware"
				]
			},
			"headers": {
				"sw-language-id": "^[a-fa-f0-9]{32}$",
				"sw-context-token": "^[\\w]{32}$",
				"sw-invalidation-states": "",
				"sw-version-id": ""
			},
			"implies": [
				"PHP",
				"MySQL",
				"jQuery",
				"Symfony"
			],
			"html": [
				"<title>shopware ([\\d\\.]+) [^<]+"
			]
		},
		"Shopery": {
			"headers": {
				"x-shopery": ""
			},
			"implies": [
				"PHP",
				"Symfony",
				"Elcodi"
			]
		},
		"HP iLO": {
			"headers": {
				"server": "hp-ilo-server(?:\/([\\d.]+))?"
			}
		},
		"Glyphicons": {
			"html": [
				"(?:<link[^>]* href=[^>]+glyphicons(?:\\.min)?\\.css|<img[^>]* src=[^>]+glyphicons)"
			]
		},
		"SmugMug": {
			"headers": {
				"smug-cdn": ""
			},
			"js": [
				"_smugsp"
			]
		},
		"Solusquare OmniCommerce Cloud": {
			"cookies": {
				"_solusquare": ""
			},
			"meta": {
				"generator": [
					"^solusquare$"
				]
			},
			"implies": [
				"Adobe ColdFusion"
			]
		},
		"Contao": {
			"meta": {
				"generator": [
					"^contao open source cms$"
				]
			},
			"html": [
				"<!--[^>]+powered by (?:typolight|contao)[^>]*-->",
				"<link[^>]+(?:typolight|contao)\\.css"
			],
			"implies": [
				"PHP"
			]
		},
		"Strato": {
			"html": [
				"<a href=\"http:\/\/www\\.strato\\.de\/\" target=\"_blank\">"
			]
		},
		"Dynamic Yield": {
			"cookies": {
				"_dy_geo": ""
			},
			"js": [
				"recommendationcontext"
			]
		},
		"Zendesk": {
			"cookies": {
				"_help_center_session": ""
			},
			"js": [
				"zendesk"
			],
			"headers": {
				"x-zendesk-user-id": ""
			}
		},
		"Qubit": {
			"js": [
				"__qubit",
				"onqubitready"
			]
		},
		"Cloudera": {
			"headers": {
				"server": "cloudera"
			}
		},
		"Cecil": {
			"meta": {
				"generator": [
					"^cecil(?: ([0-9.]+))?$"
				]
			}
		},
		"shine.js": {
			"js": [
				"shine"
			]
		},
		"WP-Statistics": {
			"implies": [
				"WordPress"
			],
			"html": [
				"<!-- analytics by wp-statistics v([\\d.]+) -"
			]
		},
		"Vizury": {
			"js": [
				"safarivizury",
				"vizury_data"
			]
		},
		"LiveIntent": {
			"js": [
				"li.advertiserid"
			]
		},
		"Ceres": {
			"headers": {
				"x-plenty-shop": "ceres"
			}
		},
		"SolidPixels": {
			"meta": {
				"web_author": [
					"^solidpixels"
				]
			},
			"implies": [
				"React"
			]
		},
		"Shapecss": {
			"js": [
				"shapecss"
			],
			"html": [
				"<link[^>]* href=\"[^\"]*shapecss(?:\\.min)?\\.css"
			]
		},
		"Riot": {
			"js": [
				"riot"
			]
		},
		"Braintree": {
			"js": [
				"braintree",
				"braintree.version"
			]
		},
		"AMP": {
			"html": [
				"<html[^>]* (?:amp|⚡)[^-]",
				"<link rel=\"amphtml\""
			]
		},
		"git": {
			"meta": {
				"generator": [
					"\\bgit\/([\\d.]+\\d)"
				]
			}
		},
		"Picreel": {
			"js": [
				"picreel"
			]
		},
		"RightJS": {
			"js": [
				"rightjs"
			]
		},
		"HCL Commerce": {
			"implies": [
				"Java"
			],
			"html": [
				"<(?:a|link|script)[^>]*(?:href|src)=\".*(?:\/wcsstore\/|webapp\\\/wcs)"
			]
		},
		"Amazon Webstore": {
			"js": [
				"amzn"
			]
		},
		"punBB": {
			"implies": [
				"PHP"
			],
			"js": [
				"punbb"
			],
			"html": [
				"powered by <a href=\"[^>]+punbb"
			]
		},
		"Strapi": {
			"headers": {
				"x-powered-by": "^strapi"
			}
		},
		"JTL Shop": {
			"cookies": {
				"jtlshop": ""
			},
			"html": [
				"(?:<input[^>]+name=\"jtlshop|<a href=\"jtl\\.php)"
			]
		},
		"jQTouch": {
			"js": [
				"jqt"
			]
		},
		"ShopGold": {
			"cookies": {
				"popup_shopgold": ""
			}
		},
		"Tamago": {
			"html": [
				"<link [^>]*href=\"http:\/\/tamago\\.temonalab\\.com"
			]
		},
		"Jive": {
			"headers": {
				"x-jive-request-id": ""
			}
		},
		"parcel": {
			"js": [
				"parcelrequire"
			]
		},
		"Tiki Wiki CMS Groupware": {
			"meta": {
				"generator": [
					"^tiki"
				]
			}
		},
		"Wink": {
			"js": [
				"wink.version"
			]
		},
		"Ruby on Rails": {
			"cookies": {
				"_session_id": ""
			},
			"meta": {
				"csrf-param": [
					"^authenticity_token$"
				]
			},
			"headers": {
				"x-powered-by": "mod_(?:rails|rack)",
				"server": "mod_(?:rails|rack)"
			},
			"implies": [
				"Ruby"
			]
		},
		"Kampyle": {
			"cookies": {
				"k_visit": ""
			},
			"js": [
				"kampyle_common",
				"k_track",
				"kampyle"
			]
		},
		"Zanox": {
			"js": [
				"zanox"
			],
			"html": [
				"<img [^>]*src=\"[^\"]+ad\\.zanox\\.com"
			]
		},
		"Amaya": {
			"meta": {
				"generator": [
					"amaya(?: v?([\\d.]+[a-z]))?"
				]
			}
		},
		"IPB": {
			"cookies": {
				"ipbwwlmodpids": ""
			},
			"js": [
				"ipboard",
				"ipb_var",
				"ipssettings"
			],
			"implies": [
				"PHP",
				"MySQL"
			],
			"html": [
				"<link[^>]+ipb_[^>]+\\.css"
			]
		},
		"EPiServer": {
			"cookies": {
				"episerver": ""
			},
			"meta": {
				"generator": [
					"episerver"
				]
			},
			"implies": [
				"Microsoft ASP.NET"
			]
		},
		"Oracle Commerce Cloud": {
			"headers": {
				"oraclecommercecloud-version": "^(.+)$"
			},
			"html": [
				"<[^>]+id=\"oracle-cc\""
			]
		},
		"uKnowva": {
			"meta": {
				"generator": [
					"uknowva (?: ([\\d.]+))?"
				]
			},
			"headers": {
				"x-content-encoded-by": "uknowva ([\\d.]+)"
			},
			"implies": [
				"PHP"
			],
			"html": [
				"<a[^>]+>powered by uknowva<\/a>"
			]
		},
		"Visa": {
			"js": [
				"visaapi",
				"visaimage",
				"visasrc"
			],
			"html": [
				"<[^>]+aria-labelledby=\"pi-visa"
			]
		},
		"mod_wsgi": {
			"headers": {
				"server": "mod_wsgi(?:\/([\\d.]+))?",
				"x-powered-by": "mod_wsgi(?:\/([\\d.]+))?"
			},
			"implies": [
				"Python",
				"Apache"
			]
		},
		"basket.js": {
			"js": [
				"basket.isvaliditem"
			]
		},
		"Miestro": {
			"meta": {
				"base_url": [
					".+\\.miestro\\.com"
				]
			}
		},
		"jQuery DevBridge Autocomplete": {
			"implies": [
				"jQuery"
			],
			"js": [
				"$.devbridgeautocomplete",
				"jquery.devbridgeautocomplete"
			]
		},
		"MaxCDN": {
			"headers": {
				"server": "^netdna",
				"x-cdn-forward": "^maxcdn$"
			}
		},
		"Jalios": {
			"meta": {
				"generator": [
					"jalios"
				]
			}
		},
		"Adobe DTM": {
			"js": [
				"_satellite.builddate"
			]
		},
		"Segmanta": {
			"js": [
				"segmanta__dynamic_embed_config",
				"segmanta__user_metadata"
			]
		},
		"Xeora": {
			"headers": {
				"server": "xeoraengine",
				"x-powered-by": "xeoracube"
			},
			"html": [
				"<input type=\"hidden\" name=\"_sys_bind_\\d+\" id=\"_sys_bind_\\d+\" \/>"
			],
			"implies": [
				"Microsoft ASP.NET"
			]
		},
		"Crypto-Loot": {
			"js": [
				"crlt.config.asmjs_name",
				"cryptoloot"
			]
		},
		"MODX": {
			"meta": {
				"generator": [
					"modx[^\\d.]*([\\d.]+)?"
				]
			},
			"js": [
				"modx",
				"modx_media_path"
			],
			"headers": {
				"x-powered-by": "^modx"
			},
			"html": [
				"<a[^>]+>powered by modx<\/a>",
				"<(?:link|script)[^>]+assets\/snippets\/",
				"<form[^>]+id=\"ajaxsearch_form",
				"<input[^>]+id=\"ajaxsearch_input"
			],
			"implies": [
				"PHP"
			]
		},
		"phpAlbum": {
			"implies": [
				"PHP"
			],
			"html": [
				"<!--phpalbum ([.\\d\\s]+)-->"
			]
		},
		"nghttpx - HTTP\/2 proxy": {
			"headers": {
				"server": "nghttpx nghttp2\/?([\\d.]+)?"
			}
		},
		"Thelia": {
			"implies": [
				"PHP",
				"Symfony"
			],
			"html": [
				"<(?:link|style|script)[^>]+\/assets\/frontoffice\/"
			]
		},
		"Stripe": {
			"cookies": {
				"__stripe_mid": ""
			},
			"js": [
				"stripe.version"
			],
			"html": [
				"<input[^>]+data-stripe"
			]
		},
		"BIGACE": {
			"meta": {
				"generator": [
					"bigace ([\\d.]+)"
				]
			},
			"html": [
				"(?:powered by <a href=\"[^>]+bigace|<!--\\s+site is running bigace)"
			],
			"implies": [
				"PHP"
			]
		},
		"VTEX": {
			"cookies": {
				"vtexfingerprint": ""
			},
			"headers": {
				"powered": "vtex",
				"server": "^vtex io$"
			}
		},
		"Immutable.js": {
			"js": [
				"immutable",
				"immutable.version"
			]
		},
		"Oracle Dynamic Monitoring Service": {
			"headers": {
				"x-oracle-dms-ecid": ""
			}
		},
		"Ada": {
			"js": [
				"__adaembedconstructor",
				"adaembed"
			]
		},
		"Enyo": {
			"js": [
				"enyo"
			]
		},
		"math.js": {
			"js": [
				"mathjs"
			]
		},
		"Solodev": {
			"headers": {
				"solodev_session": ""
			},
			"html": [
				"<div class=[\"']dynamicdiv[\"'] id=[\"']dd\\.\\d\\.\\d(?:\\.\\d)?[\"']>"
			],
			"implies": [
				"PHP"
			]
		},
		"Business Catalyst": {
			"html": [
				"<!-- bc_obnw -->"
			]
		},
		"Gogs": {
			"cookies": {
				"i_like_gogits": ""
			},
			"html": [
				"<div class=\"ui left\">\\n\\s+© \\d{4} gogs version: ([\\d.]+) page:",
				"<button class=\"ui basic clone button\" id=\"repo-clone-ssh\" data-link=\"gogs@"
			],
			"meta": {
				"keywords": [
					"go, git, self-hosted, gogs"
				]
			}
		},
		"UsableNet": {
			"html": [
				"<iframe[ˆ>]*\\.usablenet\\.com\/pt\/"
			]
		},
		"RebelMouse": {
			"headers": {
				"x-rebelmouse-cache-control": ""
			},
			"html": [
				"<!-- powered by rebelmouse\\."
			]
		},
		"VuePress": {
			"meta": {
				"generator": [
					"^vuepress(?: ([0-9.]+))?$"
				]
			},
			"implies": [
				"Vue.js"
			]
		},
		"DNN": {
			"cookies": {
				"dotnetnukeanonymous": ""
			},
			"meta": {
				"generator": [
					"dotnetnuke"
				]
			},
			"js": [
				"dotnetnuke",
				"dnn.apiversion"
			],
			"headers": {
				"x-compressed-by": "dotnetnuke",
				"dnnoutputcache": "",
				"cookie": "dnn_ismobile="
			},
			"html": [
				"<!-- by dotnetnuke corporation",
				"<!-- dnn platform"
			],
			"implies": [
				"Microsoft ASP.NET"
			]
		},
		"PyroCMS": {
			"cookies": {
				"pyrocms": ""
			},
			"headers": {
				"x-streams-distribution": "pyrocms"
			},
			"implies": [
				"Laravel"
			]
		},
		"Google Cloud": {
			"headers": {
				"via": "^1\\.1 google$"
			}
		},
		"MasterkinG32 Framework": {
			"headers": {
				"x-powered-framework": "masterking(?:)"
			},
			"meta": {
				"generator": [
					"^masterking(?:)"
				]
			}
		},
		"JSEcoin": {
			"js": [
				"jsemine"
			]
		},
		"Quick.Cart": {
			"meta": {
				"generator": [
					"quick\\.cart(?: v([\\d.]+))?"
				]
			},
			"html": [
				"<a href=\"[^>]+opensolution\\.org\/\">(?:shopping cart by|sklep internetowy)"
			]
		},
		"Sphinx": {
			"js": [
				"documentation_options"
			],
			"html": [
				"created using <a href=\"https?:\/\/(?:www\\.)?sphinx-doc\\.org\/\">sphinx<\/a> ([0-9.]+)\\."
			]
		},
		"Redmine": {
			"cookies": {
				"_redmine_session": ""
			},
			"meta": {
				"description": [
					"redmine"
				]
			},
			"implies": [
				"Ruby on Rails"
			],
			"html": [
				"powered by <a href=\"[^>]+redmine"
			]
		},
		"Booxi": {
			"js": [
				"booxi",
				"booxicontroller",
				"bxe_core"
			]
		},
		"ExitIntel": {
			"js": [
				"exitintel.version",
				"exitintelaccount",
				"exitintelconfig"
			]
		},
		"Angular Material": {
			"implies": [
				"AngularJS"
			],
			"js": [
				"ngmaterial"
			]
		},
		"Kerberos": {
			"headers": {
				"www-authenticate": "^kerberos"
			}
		},
		"BuySellAds": {
			"js": [
				"_bsa",
				"_bsapro",
				"_bsap",
				"_bsap_serving_callback"
			]
		},
		"Sulu": {
			"headers": {
				"x-generator": "sulu\/?(.+)?$"
			},
			"implies": [
				"Symfony"
			]
		},
		"UNIX": {
			"headers": {
				"server": "unix"
			}
		},
		"Open eShop": {
			"meta": {
				"copyright": [
					"open eshop ?([0-9.]+)?"
				],
				"author": [
					"open-eshop\\.com"
				]
			},
			"implies": [
				"PHP"
			]
		},
		"AccessiBe": {
			"js": [
				"acsb",
				"acsbjs"
			]
		},
		"mod_perl": {
			"headers": {
				"server": "mod_perl(?:\/([\\d\\.]+))?"
			},
			"implies": [
				"Perl",
				"Apache"
			]
		},
		"Netlify": {
			"headers": {
				"server": "^netlify",
				"x-nf-request-id": ""
			}
		},
		"Salesforce Service Cloud": {
			"implies": [
				"Salesforce"
			],
			"js": [
				"embedded_svc"
			]
		},
		"Zenfolio": {
			"js": [
				"zenfolio"
			]
		},
		"AppDynamics": {
			"js": [
				"adrum.conf.agentver"
			]
		},
		"papaya CMS": {
			"implies": [
				"PHP"
			],
			"html": [
				"<link[^>]*\/papaya-themes\/"
			]
		},
		"Branch": {
			"js": [
				"branch.setbranchviewdata",
				"branch_callback__0"
			]
		},
		"Foswiki": {
			"cookies": {
				"foswikistrikeone": ""
			},
			"meta": {
				"foswiki.wikiname": [

				],
				"foswiki.servertime": [

				]
			},
			"js": [
				"foswiki"
			],
			"headers": {
				"x-foswikiaction": ""
			},
			"html": [
				"<div class=\"foswiki(?:copyright|page|main)\">"
			],
			"implies": [
				"Perl"
			]
		},
		"Docker": {
			"headers": {
				"server": "docker"
			},
			"html": [
				"<!-- this comment is expected by the docker healthcheck  -->"
			]
		},
		"Smartstore Page Builder": {
			"css": [
				"\\.g-stage \\.g-stage-root"
			],
			"html": [
				"<section[^>]+class=\"g-stage"
			],
			"implies": [
				"Microsoft ASP.NET"
			]
		},
		"Statcounter": {
			"js": [
				"_statcounter",
				"sc_project",
				"sc_security"
			]
		},
		"SIMsite": {
			"meta": {
				"sim.medium": [

				]
			}
		},
		"Recurly": {
			"js": [
				"recurly.version"
			],
			"html": [
				"<input[^>]+data-recurly"
			]
		},
		"OXID eShop": {
			"cookies": {
				"sid_key": "oxid"
			},
			"js": [
				"oxcookienote",
				"oxinputvalidator",
				"oxloginbox",
				"oxminibasket",
				"oxmodalpopup",
				"oxtopmenu"
			],
			"implies": [
				"PHP"
			]
		},
		"gunicorn": {
			"headers": {
				"server": "gunicorn(?:\/([\\d.]+))?"
			}
		},
		"Google Optimize": {
			"js": [
				"google_optimize"
			]
		},
		"imperia CMS": {
			"meta": {
				"generator": [
					"^imperia ([0-9.]{2,3})"
				],
				"x-imperia-live-info": [

				]
			},
			"html": [
				"<imp:live-info sysid=\"[0-9a-f-]+\"(?: node_id=\"[0-9\/]*\")? *\\\/>"
			],
			"implies": [
				"Perl"
			]
		},
		"MakeShopKorea": {
			"js": [
				"makeshop",
				"makeshoploguniqueid"
			]
		},
		"cart_engine": {
			"html": [
				"skins\/_common\/jscripts.css"
			]
		},
		"boonex-dolphin": {
			"html": [
				"powered by                    dolphin - <a href=\"http:\/\/www.boonex.com\/products\/dolphin"
			]
		},
		"h3c er3100": {
			"html": [
				"<title>er3100系统管理"
			],
			"implies": [
				"H3C"
			]
		},
		"phpcms": {
			"html": [
				"powered by phpcms"
			]
		},
		"itop": {
			"html": [
				"<title>itop login"
			]
		},
		"panasonic network camera": {
			"html": [
				"multicameraframe?mode=motion&language"
			]
		},
		"泛普建筑工程施工oa": {
			"html": [
				"\/dwr\/interface\/loginservice.js"
			]
		},
		"一米oa": {
			"html": [
				"\/yimioa.apk"
			]
		},
		"dtcms": {
			"html": [
				"<title>dtcms"
			]
		},
		"iptime-router": {
			"html": [
				"<title>networks - iptime"
			]
		},
		"h3c er8300g2": {
			"html": [
				"<title>er8300g2系统管理"
			],
			"implies": [
				"H3C"
			]
		},
		"dspace": {
			"html": [
				"content=\"dspace"
			]
		},
		"openeap": {
			"html": [
				"<title>openeap_统一登录门户"
			]
		},
		"freeboxos": {
			"html": [
				"<title>freebox os"
			]
		},
		"asproxy": {
			"html": [
				"surf the web invisibly using asproxy power"
			]
		},
		"carrier-ccnweb": {
			"html": [
				"<applet code=\"jlogin.class\" archive=\"jlogin.jar"
			]
		},
		"trs_wcm": {
			"html": [
				"window.location.href = \"\/wcm\";"
			]
		},
		"hishop": {
			"html": [
				"hishop.plugins.openid"
			]
		},
		"科来ras": {
			"html": [
				"<title>科来网络回溯"
			]
		},
		"bluenet-video": {
			"html": [
				"<title>bluenet video viewer version"
			]
		},
		"base": {
			"html": [
				"mailto:base@secureideas.net"
			]
		},
		"ca-siteminder": {
			"html": [
				"<!-- siteminder encoding"
			]
		},
		"dibos": {
			"html": [
				"<title>dibos - login"
			]
		},
		"entercrm": {
			"html": [
				"entercrm"
			]
		},
		"74cms": {
			"html": [
				"powered by <a href=\"http:\/\/www.74cms.com\/\"",
				"content=\"74cms.com\""
			]
		},
		"ecwapoa": {
			"html": [
				"ecwapoa"
			]
		},
		"cf-image-hosting-script": {
			"html": [
				"powered by <a href=\"http:\/\/codefuture.co.uk\/projects\/imagehost\/"
			]
		},
		"yonyou-u8": {
			"html": [
				"getfirstu8accid"
			]
		},
		"dswjcms": {
			"html": [
				"powered by dswjcms"
			]
		},
		"claroline": {
			"html": [
				"target=\"_blank\">claroline<\/a>"
			]
		},
		"huawei hg520 adsl2+ router": {
			"html": [
				"<title>huawei hg520"
			]
		},
		"fckeditor": {
			"html": [
				"new fckeditor"
			]
		},
		"adobe_golive": {
			"html": [
				"generator\" content=\"adobe golive"
			]
		},
		"天融信入侵检测系统topsentry": {
			"html": [
				"<title>天融信入侵检测系统topsentry"
			]
		},
		"schneider_quantum_140noe77101": {
			"html": [
				"indexlanguage",
				"html\/config.js"
			]
		},
		"zenoss": {
			"html": [
				"\/zport\/dmd\/"
			]
		},
		"ewebeditor": {
			"html": [
				"\/ewebeditor.htm?"
			]
		},
		"gallery": {
			"html": [
				"<title>gallery 3 installer"
			]
		},
		"synology_diskstation": {
			"html": [
				"<title>synology diskstation"
			]
		},
		"cisco sslvpn": {
			"html": [
				"\/+cscoe+\/logon.html"
			]
		},
		"star cms": {
			"html": [
				"content=\"starcms"
			]
		},
		"acti": {
			"html": [
				"<title>web configurator"
			]
		},
		"pmway_e4_crm": {
			"html": [
				"<title>e4",
				"<title>crm"
			]
		},
		"迈捷邮件系统(magicmail)": {
			"html": [
				"\/aboutus\/magicmail.gif"
			]
		},
		"Tomcat登录页": {
			"html": [
				"manager\/html"
			],
			"implies": [
				"Apache Tomcat",
				"Java"
			]
		},
		"macrec_dvr": {
			"html": [
				"<title>macrec dvr"
			]
		},
		"lumanager": {
			"html": [
				"<title>lumanager"
			]
		},
		"blueonyx": {
			"html": [
				"<title>login - blueonyx"
			]
		},
		"imgcms": {
			"html": [
				"powered by imgcms"
			]
		},
		"pineapp": {
			"html": [
				"<title>pineapp webaccess - login"
			]
		},
		"zotonic": {
			"html": [
				"powered by: zotonic"
			]
		},
		"phpoa": {
			"html": [
				"admin_img\/msg_bg.png"
			]
		},
		"asp-nuke": {
			"html": [
				"content=\"aspnuke"
			]
		},
		"tiki-wiki cms": {
			"html": [
				"jquerytiki = new object"
			]
		},
		"avcon6": {
			"html": [
				"<title>avcon6系统管理平台"
			]
		},
		"acidcat cms": {
			"html": [
				"start acidcat cms footer information"
			]
		},
		"万户网络": {
			"html": [
				"css\/css_whir.css"
			]
		},
		"interred": {
			"html": [
				"created with interred"
			]
		},
		"八哥cms": {
			"html": [
				"content=\"bagecms"
			]
		},
		"maticsoftsns_动软分享社区": {
			"html": [
				"maticsoftsns"
			]
		},
		"teamviewer": {
			"html": [
				"this site is running",
				"teamviewer"
			]
		},
		"yxcms": {
			"html": [
				"content=\"yxcms"
			]
		},
		"天融信网站监测与自动修复系统": {
			"html": [
				"<title>天融信网站监测与自动修复系统"
			]
		},
		"hikashop": {
			"html": [
				"\/media\/com_hikashop\/css\/"
			]
		},
		"元年财务软件": {
			"html": [
				"yuannian.css"
			]
		},
		"infoglue": {
			"html": [
				"<title>infoglue"
			]
		},
		"天融信topflow": {
			"html": [
				"天融信topflow"
			]
		},
		"awstats_admin": {
			"html": [
				"generator\" content=\"awstats"
			]
		},
		"javashop": {
			"html": [
				"易族智汇javashop"
			]
		},
		"Spark": {
			"html": [
				"<title>spark",
				"spark jobs"
			]
		},
		"o2ocms": {
			"html": [
				"\/index.php\/clasify\/showone\/gtitle\/"
			]
		},
		"opencart": {
			"html": [
				"powered by opencart"
			]
		},
		"dorg": {
			"html": [
				"<title>dorg - "
			]
		},
		"eticket": {
			"html": [
				"powered by eticket"
			]
		},
		"apphp-calendar": {
			"html": [
				"this script was generated by apphp calendar"
			]
		},
		"amiro-cms": {
			"html": [
				"powered by: amiro cms"
			]
		},
		"aspthai_net-webboard": {
			"html": [
				"aspthai.net webboard"
			]
		},
		"lynxspring_jenesys": {
			"html": [
				"lx jenesys"
			]
		},
		"同城多用户商城": {
			"html": [
				"style_chaoshi"
			]
		},
		"appcms": {
			"html": [
				"powerd by appcms"
			]
		},
		"siteserver": {
			"html": [
				"<title>powered by siteserver cms"
			]
		},
		"bacula-web": {
			"html": [
				"<title>webacula"
			]
		},
		"锐捷 rg-dbs": {
			"html": [
				"\/dbaudit\/authenticate"
			]
		},
		"cpassman": {
			"html": [
				"<title>collaborative passwords manager"
			]
		},
		"mediawiki": {
			"html": [
				"powered by mediawiki"
			]
		},
		"avaya-aura-utility-server": {
			"html": [
				"vmstitle\">avaya aura&#8482;&nbsp;utility server"
			]
		},
		"genieatm": {
			"html": [
				"<title>genieatm"
			]
		},
		"apabi数字资源平台": {
			"html": [
				"<title>数字资源平台"
			]
		},
		"bluecms": {
			"html": [
				"power by bcms"
			]
		},
		"phpshe": {
			"html": [
				"powered by phpshe"
			]
		},
		"cdr-stats": {
			"html": [
				"<title>cdr-stats | customer interface"
			]
		},
		"edito-cms": {
			"html": [
				"title=\"cms\" href=\"http:\/\/www.edito.pl\/"
			]
		},
		"bbpress": {
			"html": [
				"is proudly powered by <a href=\"http:\/\/bbpress.org"
			]
		},
		"地平线cms": {
			"html": [
				"<title>powered by deep soon"
			]
		},
		"huawei inner web": {
			"html": [
				"<title>huawei inner web"
			]
		},
		"h3c router": {
			"html": [
				"\/wnm\/ssl\/web\/frame\/login.html"
			],
			"implies": [
				"H3C"
			]
		},
		"clansphere": {
			"html": [
				"index.php?mod=clansphere&amp;action=about"
			]
		},
		"edusoho开源网络课堂": {
			"html": [
				"<title>edusoho"
			]
		},
		"正方教务管理系统": {
			"html": [
				"style\/base\/jw.css"
			]
		},
		"ideacms": {
			"html": [
				"powered by ideacms"
			]
		},
		"iwebsns": {
			"html": [
				"\/jooyea\/images\/snslogo.gif"
			]
		},
		"dadabik": {
			"html": [
				"content=\"dadabik"
			]
		},
		"沃科网异网同显系统": {
			"html": [
				"<title>异网同显系统"
			]
		},
		"rap": {
			"html": [
				"\/jscripts\/rap_util.js"
			]
		},
		"informatics-cms": {
			"html": [
				"content=\"informatics"
			]
		},
		"jobberbase": {
			"html": [
				"jobber.performsearch"
			]
		},
		"niucms": {
			"html": [
				"content=\"niucms"
			]
		},
		"e-xoopport": {
			"html": [
				"powered by e-xoopport"
			]
		},
		"infomaster": {
			"html": [
				"\/masterview\/mpleftnavstyle\/panelbar.mpifma.css"
			]
		},
		"h3c er2100": {
			"html": [
				"<title>er2100系统管理"
			],
			"implies": [
				"H3C"
			]
		},
		"acidcat_cms": {
			"html": [
				"start acidcat cms footer information"
			]
		},
		"foxphp": {
			"html": [
				"foxphpscroll"
			]
		},
		".net": {
			"html": [
				"content=\"visual basic .net 7.1"
			]
		},
		"贷齐乐p2p": {
			"html": [
				"src=\"\/js\/jpackage"
			]
		},
		"tp-shop": {
			"html": [
				"mn-c-top"
			]
		},
		"airvaecommerce": {
			"html": [
				"e-commerce shopping cart software"
			]
		},
		"thinksaas": {
			"html": [
				"\/app\/home\/skins\/default\/style.css"
			]
		},
		"contao": {
			"html": [
				"system\/contao.css"
			]
		},
		"wdcp": {
			"html": [
				"<title>wdcp服务器"
			]
		},
		"techbridge": {
			"html": [
				"sorry,you need to use ie brower"
			]
		},
		"dolphin": {
			"html": [
				"bx_css_async"
			]
		},
		"wdlinux": {
			"html": [
				"<title>wdos"
			]
		},
		"eadmin": {
			"html": [
				"<title>eadmin"
			]
		},
		"u-mail": {
			"html": [
				"<body link=\"white\" vlink=\"white\" alink=\"white\">"
			]
		},
		"iqeye-netcam": {
			"html": [
				"<title>iqeye: live images"
			]
		},
		"huawei hg630": {
			"html": [
				"<title>huawei hg630"
			]
		},
		"etano": {
			"html": [
				"powered by <a href=\"http:\/\/www.datemill.com"
			]
		},
		"h3c er6300": {
			"html": [
				"<title>er6300系统管理"
			],
			"implies": [
				"H3C"
			]
		},
		"dnp firewall": {
			"html": [
				"powered by dnp firewall"
			]
		},
		"sdcms": {
			"html": [
				"<title>powered by sdcms"
			]
		},
		"zte_zsrv2_router": {
			"html": [
				"<title>zsrv2路由器web管理系统",
				"zte corporation. all rights reserved."
			]
		},
		"中企动力门户cms": {
			"html": [
				"中企动力提供技术支持"
			]
		},
		"天融信异常流量管理与抗拒绝服务系统": {
			"html": [
				"<title>天融信异常流量管理与抗拒绝服务系统"
			]
		},
		"dzcp": {
			"html": [
				"<!--[ dzcp"
			]
		},
		"h3c am8000": {
			"html": [
				"<title>am8000"
			],
			"implies": [
				"H3C"
			]
		},
		"dbshop": {
			"html": [
				"content=\"dbshop"
			]
		},
		"phpok": {
			"html": [
				"<title>phpok"
			]
		},
		"activecollab": {
			"html": [
				"powered by activecollab"
			]
		},
		"burning-board-lite": {
			"html": [
				"powered by <b>burning board"
			]
		},
		"evo-cam": {
			"html": [
				"value=\"evocam.jar"
			]
		},
		"h3c-secblade-firewall": {
			"html": [
				"js\/mulplatapi.js"
			],
			"implies": [
				"H3C"
			]
		},
		"h3c er3108g": {
			"html": [
				"<title>er3108g系统管理"
			],
			"implies": [
				"H3C"
			]
		},
		"donations-cloud": {
			"html": [
				"\/donationscloud.css"
			]
		},
		"cisco-ip-phone": {
			"html": [
				"cisco unified wireless ip phone"
			]
		},
		"畅捷通": {
			"html": [
				"<title>畅捷通"
			]
		},
		"逐浪zoomla": {
			"html": [
				"script src=\"http:\/\/code.zoomla.cn\/"
			]
		},
		"jagoanstore": {
			"html": [
				"href=\"http:\/\/www.jagoanstore.com\/\" target=\"_blank\">toko online"
			]
		},
		"h3c路由器": {
			"html": [
				"<title>web user login",
				"nlanguagesupported"
			],
			"implies": [
				"H3C"
			]
		},
		"e-junkie": {
			"html": [
				"function ejejc_lc"
			]
		},
		"emlog-php": {
			"html": [
				"\/include\/lib\/js\/common_tpl.js",
				"content\/templates"
			]
		},
		"sony摄像头": {
			"html": [
				"<title>sony network camera"
			]
		},
		"allomani": {
			"html": [
				"programmed by allomani"
			]
		},
		"efront": {
			"html": [
				"<a href = \"http:\/\/www.efrontlearning.net"
			]
		},
		"telerik sitefinity": {
			"html": [
				"telerik.web.ui.webresource.axd"
			]
		},
		"contentxxl": {
			"html": [
				"content=\"contentxxl"
			]
		},
		"duomicms": {
			"html": [
				"<title>power by duomicms"
			]
		},
		"cgiproxy": {
			"html": [
				"<a href=\"http:\/\/www.jmarshall.com\/tools\/cgiproxy\/"
			]
		},
		"google-talk-chatback": {
			"html": [
				"www.google.com\/talk\/service\/"
			]
		},
		"ultra_electronics": {
			"html": [
				"\/preauth\/style.css"
			]
		},
		"万网企业云邮箱": {
			"html": [
				"static.mxhichina.com\/images\/favicon.ico"
			]
		},
		"array_networks_vpn": {
			"html": [
				"an_util.js"
			]
		},
		"e-bridge": {
			"html": [
				"e-bridge"
			]
		},
		"euse_study": {
			"html": [
				"userinfo\/userfp.aspx"
			]
		},
		"锐捷应用控制引擎": {
			"html": [
				"<title>锐捷应用控制引擎"
			]
		},
		"shopex": {
			"html": [
				"content=\"shopex"
			]
		},
		"ebuilding-network-controller": {
			"html": [
				"<title>ebuilding web"
			]
		},
		"华为（huawei）安全设备": {
			"html": [
				"sweb-lib\/resource\/"
			]
		},
		"小脑袋": {
			"html": [
				"http:\/\/stat.xiaonaodai.com\/stat.php"
			]
		},
		"智睿软件": {
			"html": [
				"zhirui.js"
			]
		},
		"校园卡管理系统": {
			"html": [
				"harbin synjones electronic"
			]
		},
		"edmwebvideo": {
			"html": [
				"<title>edmwebvideo"
			]
		},
		"任我行crm": {
			"html": [
				"<title>任我行crm"
			]
		},
		"牛逼cms": {
			"html": [
				"content=\"niubicms"
			]
		},
		"h3c er3108gw": {
			"html": [
				"<title>er3108gw系统管理"
			],
			"implies": [
				"H3C"
			]
		},
		"jgs-portal": {
			"html": [
				"powered by <b>jgs-portal version"
			]
		},
		"ananyoo-cms": {
			"html": [
				"content=\"http:\/\/www.ananyoo.com"
			]
		},
		"adobe_robohelp": {
			"html": [
				"generator\" content=\"adobe robohelp"
			]
		},
		"indusguard_waf": {
			"html": [
				"<title>indusguard waf",
				"wafportal\/wafportal.nocache.js"
			]
		},
		"aja-video-converter": {
			"html": [
				"eparamid_swversion"
			]
		},
		"天融信安全管理系统": {
			"html": [
				"<title>天融信安全管理"
			]
		},
		"recaptcha": {
			"html": [
				"recaptcha_ajax.js"
			]
		},
		"yonyoufe": {
			"html": [
				"<title>fe协作"
			]
		},
		"jcg无线路由器": {
			"html": [
				"<title>wireless router",
				"http:\/\/www.jcgcn.com"
			]
		},
		"geeklog": {
			"html": [
				"powered by <a href=\"http:\/\/www.geeklog.net\/"
			]
		},
		"boastmachine": {
			"html": [
				"powered by boastmachine"
			]
		},
		"zkaccess 门禁管理系统": {
			"html": [
				"\/logozkaccess_zh-cn.jpg"
			]
		},
		"everything": {
			"html": [
				"everything.gif"
			]
		},
		"ap-router": {
			"html": [
				"<title>ap router new generation"
			]
		},
		"vicworl": {
			"html": [
				"vindex_right_d"
			]
		},
		"lanmp一键安装包": {
			"html": [
				"<title>lanmp一键安装包"
			]
		},
		"soffice": {
			"html": [
				"<title>oa办公管理平台"
			]
		},
		"gpsweb": {
			"html": [
				"<title>gpsweb"
			]
		},
		"egroupware": {
			"html": [
				"content=\"egroupware"
			]
		},
		"dwr": {
			"html": [
				"\/dwr\/engine.js"
			]
		},
		"soeasy网站集群系统": {
			"html": [
				"<title>soeasy网站集群"
			]
		},
		"winwebmail": {
			"html": [
				"<title>winwebmail"
			]
		},
		"epiware": {
			"html": [
				"epiware - project and document management"
			]
		},
		"dnp-firewall": {
			"html": [
				"<title>forum gateway - powered by dnp firewall"
			]
		},
		"edirectory": {
			"html": [
				"target=\"_blank\">edirectory&trade"
			]
		},
		"biscom-delivery-server": {
			"html": [
				"\/bds\/stylesheets\/fds.css"
			]
		},
		"juniper_vpn": {
			"html": [
				"welcome.cgi?p=logo"
			]
		},
		"auto-cms": {
			"html": [
				"powered by auto cms"
			]
		},
		"网神防火墙": {
			"html": [
				"<title>secgate 3600"
			]
		},
		"earlyimpact-productcart": {
			"html": [
				"fpassword.asp?redirecturl=&frurl=custva.asp"
			]
		},
		"visualsvn": {
			"html": [
				"<title>visualsvn server"
			]
		},
		"phpmps": {
			"html": [
				"templates\/phpmps\/style\/index.css"
			]
		},
		"orocrm": {
			"html": [
				"\/bundles\/oroui\/"
			]
		},
		"baocms": {
			"html": [
				"<title>baocms"
			]
		},
		"huawei b683": {
			"html": [
				"<title>huawei b683"
			]
		},
		"alumniserver": {
			"html": [
				"content=\"alumni"
			]
		},
		"echo": {
			"html": [
				"powered by echo"
			]
		},
		"kajona": {
			"html": [
				"powered by kajona"
			]
		},
		"elite-gaming-ladders": {
			"html": [
				"powered by elite"
			]
		},
		"埃森诺网络服务质量检测系统": {
			"html": [
				"<title>埃森诺网络服务质量检测系统 "
			]
		},
		"airtiesrouter": {
			"html": [
				"<title>airties"
			]
		},
		"onssi_video_clients": {
			"html": [
				"<title>onssi video clients"
			]
		},
		"xfinity": {
			"html": [
				"<title>xfinity"
			]
		},
		"dvr-webclient": {
			"html": [
				"<title>dvr-webclient"
			]
		},
		"捷点jcms": {
			"html": [
				"publish by jcms2010"
			]
		},
		"华为 mcu": {
			"html": [
				"<title>huawei mcu"
			]
		},
		"金蝶政务gsis": {
			"html": [
				"\/kdgs\/script\/kdgs.js"
			]
		},
		"cowiki": {
			"html": [
				"content=\"cowiki"
			]
		},
		"e-tiller": {
			"html": [
				"reader\/view_abstract.aspx"
			]
		},
		"yonyou nc": {
			"html": [
				"uclient.yonyou.com"
			]
		},
		"genohm-scada": {
			"html": [
				"<title>genohm scada launcher"
			]
		},
		"惠尔顿上网行为管理系统": {
			"html": [
				"updateloginpswd.php",
				"passroedele"
			]
		},
		"elitius": {
			"html": [
				"target=\"_blank\" title=\"affiliate"
			]
		},
		"易点cms": {
			"html": [
				"diancms_用户登陆引用"
			]
		},
		"oracle_opera": {
			"html": [
				"<title>micros systems inc., opera"
			]
		},
		"help-desk-software": {
			"html": [
				"target=\"_blank\">freehelpdesk.org"
			]
		},
		"zte_mifi_une": {
			"html": [
				"<title>mifi une 4g lte"
			]
		},
		"帝友p2p": {
			"html": [
				"src=\"\/dyweb\/dythemes"
			]
		},
		"astaro-command-center": {
			"html": [
				"\/js\/_variables_from_backend.js?"
			]
		},
		"wimax_cpe": {
			"html": [
				"<title>wimax cpe configuration"
			]
		},
		"ibm-cognos": {
			"html": [
				"cognos &#26159; international business machines corp"
			]
		},
		"jtbc(cms)": {
			"html": [
				"content=\"jtbc"
			]
		},
		"commonspot": {
			"html": [
				"content=\"commonspot"
			]
		},
		"aspilot-cart": {
			"html": [
				"content=\"pilot cart"
			]
		},
		"kingcms": {
			"html": [
				"<title>kingcms"
			]
		},
		"ourphp": {
			"html": [
				"powered by ourphp"
			]
		},
		"bitweaver": {
			"html": [
				"href=\"http:\/\/www.bitweaver.org\">powered by"
			]
		},
		"paloalto_firewall": {
			"html": [
				"access to the web page you were trying to visit has been blocked in accordance with company policy"
			]
		},
		"astaro-security-gateway": {
			"html": [
				"wfe\/asg\/js\/app_selector.js?t="
			]
		},
		"f3site": {
			"html": [
				"powered by <a href=\"http:\/\/compmaster.prv.pl"
			]
		},
		"bomgar": {
			"html": [
				"alt=\"remote support by bomgar"
			]
		},
		"mymps": {
			"html": [
				"<title>mymps"
			]
		},
		"zcms": {
			"html": [
				"<title>zcms泽元内容管理"
			]
		},
		"awstats": {
			"html": [
				"awstats.pl?config="
			]
		},
		"phpinfo": {
			"html": [
				"<title>phpinfo",
				"virtual directory support"
			]
		},
		"小米路由器": {
			"html": [
				"<title>小米路由器\" "
			]
		},
		"dorado": {
			"html": [
				"<title>dorado login page"
			]
		},
		"dell openmanage switch administrator": {
			"html": [
				"<title>dell openmanage switch administrator"
			]
		},
		"biromsoft-webcam": {
			"html": [
				"<title>biromsoft webcam"
			]
		},
		"citrix-xenserver": {
			"html": [
				"citrix systems, inc. xenserver"
			],
			"implies": [
				"Citrix"
			]
		},
		"phpb2b": {
			"html": [
				"powered by phpb2b"
			]
		},
		"乐视路由器": {
			"html": [
				"<title>乐视路由器",
				"<div class=\"login-logo\"><\/div>"
			]
		},
		"ubnt_unifi系列路由": {
			"html": [
				"<title>unifi",
				"<div class=\"appglobalheader\">"
			]
		},
		"蓝盾bdwebguard": {
			"html": [
				"background: url(images\/loginbg.jpg) #e5f1fc"
			]
		},
		"科信邮件系统": {
			"html": [
				"lo_computername"
			]
		},
		"希尔oa": {
			"html": [
				"\/heeroa\/login.do"
			]
		},
		"netdvrv3": {
			"html": [
				"objlvrfornoie"
			]
		},
		"munin": {
			"html": [
				"munin-month.html"
			]
		},
		"zyxel": {
			"html": [
				"forms\/rpauth_1"
			]
		},
		"ip.board": {
			"html": [
				"ipb.vars"
			]
		},
		"梭子鱼防火墙": {
			"html": [
				"http:\/\/www.barracudanetworks.com?a=bsf_product\" class=\"transbutton",
				"\/cgi-mod\/header_logo.cgi"
			]
		},
		"browsercms": {
			"html": [
				"powered by browsercms"
			]
		},
		"shopnc": {
			"html": [
				"powered by shopnc"
			]
		},
		"cuumall": {
			"html": [
				"power by cuumall"
			]
		},
		"一采通": {
			"html": [
				"\/custom\/groupnewslist.aspx?groupid="
			]
		},
		"linksys_spa_configuration ": {
			"html": [
				"<title>linksys spa configuration"
			]
		},
		"睿博士云办公系统": {
			"html": [
				"\/user\/toupdatepasswordpage.di"
			]
		},
		"jxt-consulting": {
			"html": [
				"powered by jxt consulting"
			]
		},
		"sophos_web_appliance": {
			"html": [
				"<title>sophos web appliance"
			]
		},
		"webplus": {
			"html": [
				"webplus",
				"高校网站群管理平台"
			]
		},
		"aruba-device": {
			"html": [
				"\/images\/arubalogo.gif"
			]
		},
		"dokuwiki": {
			"html": [
				"powered by dokuwiki"
			]
		},
		"basilic": {
			"html": [
				"\/software\/basilic"
			]
		},
		"gatequest-php-site-recommender": {
			"html": [
				"<title>gatequest"
			]
		},
		"brewblogger": {
			"html": [
				"developed by <a href=\"http:\/\/www.zkdigital.com"
			]
		},
		"中望oa": {
			"html": [
				"\/images\/default\/first\/xtoa_logo.png"
			]
		},
		"filenice": {
			"html": [
				"filenice\/filenice.js"
			]
		},
		"ikonboard": {
			"html": [
				"powered by <a href=\"http:\/\/www.ikonboard.com"
			]
		},
		"fossil": {
			"html": [
				"<a href=\"http:\/\/fossil-scm.org"
			]
		},
		"任我行电商": {
			"html": [
				"content=\"366ec"
			]
		},
		"青果软件": {
			"html": [
				"<title>kingosoft"
			]
		},
		"wuzhicms": {
			"html": [
				"powered by wuzhicms"
			]
		},
		"iwebshop": {
			"html": [
				"\/runtime\/default\/systemjs"
			]
		},
		"cituscms": {
			"html": [
				"powered by cituscms"
			]
		},
		"久其通用财表系统": {
			"html": [
				"<nobr>北京久其软件股份有限公司"
			]
		},
		"d-link_voip_wireless_router": {
			"html": [
				"<title>d-link voip wireless router"
			]
		},
		"forest-blog": {
			"html": [
				"<title>forest blog"
			]
		},
		"apache-wicket": {
			"html": [
				"xmlns:wicket="
			]
		},
		"bestshoppro": {
			"html": [
				"content=\"www.bst.pl"
			]
		},
		"金龙卡金融化一卡通网站查询子系统": {
			"html": [
				"<title>金龙卡金融化一卡通网站查询子系统"
			]
		},
		"comcast_business": {
			"html": [
				"cmn\/css\/common-min.css"
			]
		},
		"金蝶eas": {
			"html": [
				"eassessionid"
			]
		},
		"dokeos": {
			"html": [
				"name=\"generator\" content=\"dokeos"
			]
		},
		"金笛邮件系统": {
			"html": [
				"\/jdwm\/cgi\/login.cgi?login"
			]
		},
		"apache-forrest": {
			"html": [
				"name=\"forrest"
			]
		},
		"cruxcms": {
			"html": [
				"title=\"cruxcms\" class=\"blank"
			]
		},
		"vzpp plesk": {
			"html": [
				"<title>vzpp plesk "
			]
		},
		"hostbill": {
			"html": [
				"powered by <a href=\"http:\/\/hostbillapp.com"
			]
		},
		"e-manage-myschool": {
			"html": [
				"e-manage all rights reserved myschool version"
			]
		},
		"h3c er6300g2": {
			"html": [
				"<title>er6300g2系统管理"
			],
			"implies": [
				"H3C"
			]
		},
		"tipask": {
			"html": [
				"content=\"tipask"
			]
		},
		"wordpress-php": {
			"html": [
				"wp-user"
			]
		},
		"aspcms": {
			"html": [
				"<title>powered by aspcms"
			]
		},
		"fengcms": {
			"html": [
				"powered by fengcms"
			]
		},
		"parallels plesk panel": {
			"html": [
				"parallels ip holdings gmbh"
			]
		},
		"esitesbuilder": {
			"html": [
				"esitesbuilder. all rights reserved"
			]
		},
		"centreon": {
			"html": [
				"<title>centreon - it & network monitoring"
			]
		},
		"百为路由": {
			"html": [
				"提交验证的id必须是ctl_submit"
			]
		},
		"bugtracker.net": {
			"html": [
				"valign=middle><a href=http:\/\/ifdefined.com\/bugtrackernet.html>"
			]
		},
		"b2evolution": {
			"html": [
				"powered by b2evolution"
			]
		},
		"大米cms": {
			"html": [
				"<title>大米cms-"
			]
		},
		"jcore": {
			"html": [
				"jcore_version = "
			]
		},
		"car-portal": {
			"html": [
				"powered by <a href=\"http:\/\/www.netartmedia.net\/carsportal"
			]
		},
		"lotus": {
			"html": [
				"<title>ibm lotus inotes login"
			]
		},
		"turbomail": {
			"html": [
				"<title>turbomail邮件系统"
			]
		},
		"ezoffice": {
			"html": [
				"<title>万户oa"
			]
		},
		"云因网上书店": {
			"html": [
				"main\/building.cfm"
			]
		},
		"destoon": {
			"html": [
				"destoon_moduleid"
			]
		},
		"rg-powercache内容加速系统": {
			"html": [
				"<title>rg-powercache"
			]
		},
		"chillycms": {
			"html": [
				"powered by <a href=\"http:\/\/frozenpepper.de"
			]
		},
		"天融信网络审计系统": {
			"html": [
				"onclick=\"dlg_download()"
			]
		},
		"1und1": {
			"html": [
				"\/shop\/catalog\/browse?sessid="
			]
		},
		"espcms": {
			"html": [
				"<title>powered by espcms"
			]
		},
		"netsurveillance": {
			"html": [
				"<title>netsurveillance"
			]
		},
		"dublincore": {
			"html": [
				"name=\"dc.title"
			]
		},
		"武汉弘智科技": {
			"html": [
				"研发与技术支持：武汉弘智科技有限公司"
			]
		},
		"mrtg": {
			"html": [
				"<title>mrtg index page"
			]
		},
		"extplorer": {
			"html": [
				"<title>login - extplorer"
			]
		},
		"advanced-image-hosting-script": {
			"html": [
				"welcome to install aihs script"
			]
		},
		"kampyle": {
			"html": [
				"start kampyle feedback form button"
			]
		},
		"cmsimple": {
			"html": [
				"powered by cmsimple.dk"
			]
		},
		"polycom": {
			"html": [
				"<title>polycom",
				"kallowdirecthtmlfileaccess"
			]
		},
		"hp_ilo(hp_integrated_lights-out)": {
			"html": [
				"js\/ilo.js"
			]
		},
		"3com nbx": {
			"html": [
				"<title>nbx netset"
			]
		},
		"gcards": {
			"html": [
				"<a href=\"http:\/\/www.gregphoto.net\/gcards\/index.php"
			]
		},
		"dt-centrepiece": {
			"html": [
				"powered by dt centrepiece"
			]
		},
		"v5shop": {
			"html": [
				"<title>v5shop"
			]
		},
		"通达oa": {
			"html": [
				"office anywhere 2013"
			]
		},
		"微普外卖点餐系统": {
			"html": [
				"userfiles\/shoppics\/"
			]
		},
		"av-arcade": {
			"html": [
				"powered by <a href=\"http:\/\/www.avscripts.net\/avarcade\/"
			]
		},
		"yonyou-ufida": {
			"html": [
				"\/system\/login\/login.asp?appid="
			]
		},
		"scientific-atlanta_cable_modem": {
			"html": [
				"<title>scientific-atlanta cable modem"
			]
		},
		"汉柏安全网关": {
			"html": [
				"<title>opzoon - "
			]
		},
		"semcms": {
			"html": [
				"semcms php"
			]
		},
		"imageview": {
			"html": [
				"href=\"http:\/\/www.blackdot.be\" title=\"blackdot.be"
			]
		},
		"zoneminder": {
			"html": [
				"zoneminder login"
			]
		},
		"redmine": {
			"html": [
				"redmine"
			]
		},
		"anecms": {
			"html": [
				"content=\"erwin aligam - ealigam@gmail.com"
			]
		},
		"1024cms": {
			"html": [
				"powered by 1024 cms"
			]
		},
		"h3c er2100v2": {
			"html": [
				"<title>er2100v2系统管理"
			],
			"implies": [
				"H3C"
			]
		},
		"samsung dvr": {
			"html": [
				"<title>samsung dvr"
			]
		},
		"shoutcast": {
			"html": [
				"<title>shoutcast administrator"
			]
		},
		"h3c er5200": {
			"html": [
				"<title>er5200系统管理"
			],
			"implies": [
				"H3C"
			]
		},
		"cogent-datahub": {
			"html": [
				"<title>cogent datahub webview"
			]
		},
		"silverstripe": {
			"html": [
				"content=\"silverstripe"
			]
		},
		"网御waf": {
			"html": [
				"<title>网御waf"
			]
		},
		"stcms": {
			"html": [
				"dahongy<dahongy@gmail.com>"
			]
		},
		"北京清科锐华cemis": {
			"html": [
				"\/theme\/2009\/image"
			]
		},
		"cameralife": {
			"html": [
				"this site is powered by camera life"
			]
		},
		"ibm-bladecenter": {
			"html": [
				"alt=\"ibm bladecenter"
			]
		},
		"artiphp-cms": {
			"html": [
				"copyright artiphp"
			]
		},
		"wishoa": {
			"html": [
				"wishoa_webplugin.js"
			]
		},
		"dv-cart": {
			"html": [
				"class=\"kt_tngtable"
			]
		},
		"科迈ras系统": {
			"html": [
				"<title>科迈ras"
			]
		},
		"isolsoft-support-center": {
			"html": [
				"powered by: support center"
			]
		},
		"oracle_applicaton_server": {
			"html": [
				"oralightheadersub"
			]
		},
		"rcms": {
			"html": [
				"\/r\/cms\/www\/"
			]
		},
		"huawei smc": {
			"html": [
				"script\/smcscript.js?version="
			]
		},
		"intellinet-ip-camera": {
			"html": [
				"http:\/\/www.intellinet-network.com\/driver\/netcam.exe"
			]
		},
		"华天动力oa(oa8000)": {
			"html": [
				"\/oaapp\/webobjects\/oaapp.woa"
			]
		},
		"episerver": {
			"html": [
				"content=\"episerver"
			]
		},
		"b2bbuilder": {
			"html": [
				"translatebuttonid = \"b2bbuilder"
			]
		},
		"finecms": {
			"html": [
				"powered by finecms"
			]
		},
		"ilo": {
			"html": [
				"<title>hp integrated lights-out"
			]
		},
		"cyn_in": {
			"html": [
				"powered by cyn.in"
			]
		},
		"dugallery": {
			"html": [
				"powered by duportal"
			]
		},
		"interspire-shopping-cart": {
			"html": [
				"content=\"interspire shopping cart"
			]
		},
		"MetInfo": {
			"meta": {
				"generator": [
					"metinfo( [\\d.]+)?"
				]
			},
			"html": [
				"<title>powered by metinfo",
				"metinfo.css"
			]
		},
		"arrisi_touchstone": {
			"html": [
				"<title>touchstone status"
			]
		},
		"fortiguard": {
			"html": [
				"<title>web filter block override"
			]
		},
		"magento": {
			"html": [
				"magento, varien, e-commerce"
			]
		},
		"exponent-cms": {
			"html": [
				"powered by exponent cms"
			]
		},
		"snb股票交易软件": {
			"html": [
				"copyright 2005–2009 <a href=\"http:\/\/www.s-mo.com\">"
			]
		},
		"axis-printserver": {
			"html": [
				"psb_printjobs.gif"
			]
		},
		"h3c公司产品": {
			"html": [
				"service@h3c.com"
			],
			"implies": [
				"H3C"
			]
		},
		"凡科": {
			"html": [
				"凡科互联网科技股份有限公司"
			]
		},
		"moosefs": {
			"html": [
				"under-goal files"
			]
		},
		"福富安全基线管理": {
			"html": [
				"align=\"center\">福富软件"
			]
		},
		"publiccms": {
			"html": [
				"<title>publiccms"
			]
		},
		"contentteller-cms": {
			"html": [
				"content=\"esselbach contentteller cms"
			]
		},
		"fastpublish-cms": {
			"html": [
				"content=\"fastpublish"
			]
		},
		"edimax": {
			"html": [
				"<title>edimax technology"
			]
		},
		"cisco-vpn-3000-concentrator": {
			"html": [
				"<title>cisco systems, inc. vpn 3000 concentrator"
			]
		},
		"collabtive": {
			"html": [
				"<title>login @ collabtive"
			]
		},
		"fangmail": {
			"html": [
				"\/fangmail\/default\/css\/em_css.css"
			]
		},
		"asp168欧虎": {
			"html": [
				"upload\/moban\/images\/style.css"
			]
		},
		"hp-officejet-printer": {
			"html": [
				"<title>hp officejet"
			]
		},
		"帕拉迪统一安全管理和综合审计系统": {
			"html": [
				"module\/image\/pldsec.css"
			]
		},
		"dotclear": {
			"html": [
				"powered by <a href=\"http:\/\/dotclear.org\/"
			]
		},
		"capexweb": {
			"html": [
				"name=\"dfparentdb"
			]
		},
		"motorola_sbg900": {
			"html": [
				"<title>motorola sbg900"
			]
		},
		"invisionpowerboard": {
			"html": [
				"powered by <a href=\"http:\/\/www.invisionboard.com"
			]
		},
		"regentapi_v2.0": {
			"html": [
				"regentapi_v2.0"
			]
		},
		"observa telcom": {
			"html": [
				"<title>observa"
			]
		},
		"loyaa信息自动采编系统": {
			"html": [
				"\/loyaa\/common.lib.js"
			]
		},
		"bigace": {
			"html": [
				"site is running bigace"
			]
		},
		"basic-php-events-lister": {
			"html": [
				"powered by: <a href=\"http:\/\/www.mevin.com\/\">"
			]
		},
		"testlink": {
			"html": [
				"testlink_library.js"
			]
		},
		"blogengine_net": {
			"html": [
				"pics\/blogengine.ico"
			]
		},
		"intraxxion-cms": {
			"html": [
				"content=\"intraxxion"
			]
		},
		"rabbitmq": {
			"html": [
				"<title>rabbitmq management<\/title>"
			]
		},
		"hiki": {
			"html": [
				"content=\"hiki"
			]
		},
		"斐讯fortress": {
			"html": [
				"<title>斐讯fortress防火墙",
				"<meta name=\"author\" content=\"上海斐讯数据通信技术有限公司\" \/>"
			]
		},
		"kaibb": {
			"html": [
				"powered by kaibb"
			]
		},
		"elxis-cms": {
			"html": [
				"content=\"elxis"
			]
		},
		"cinvoice": {
			"html": [
				"powered by <a href=\"http:\/\/www.forperfect.com\/"
			]
		},
		"海天oa": {
			"html": [
				"htvos.js"
			]
		},
		"iscripts-reservelogic": {
			"html": [
				"powered by <a href=\"http:\/\/www.iscripts.com\/reservelogic\/"
			]
		},
		"geonode": {
			"html": [
				"powered by <a href=\"http:\/\/geonode.org"
			]
		},
		"adobe_ cq5": {
			"html": [
				"_jcr_content"
			]
		},
		"锐捷nbr路由器": {
			"html": [
				"free_nbr_login_form.png"
			]
		},
		"we7": {
			"html": [
				"\/widgets\/widgetcollection\/"
			]
		},
		"kesioncms": {
			"html": [
				"publish by kesioncms"
			]
		},
		"海洋cms": {
			"html": [
				"<title>seacms"
			]
		},
		"中控智慧时间安全管理平台": {
			"html": [
				"<title>zkeco 时间&安全管理平台"
			]
		},
		"sophos web appliance": {
			"html": [
				"<title>sophos web appliance"
			]
		},
		"scada plc": {
			"html": [
				"ethernet processor"
			]
		},
		"backbee": {
			"html": [
				"<div id=\"bb5-site-wrapper\">"
			]
		},
		"alstrasoft-askme": {
			"html": [
				"<a href=\"pass_recover.php\">"
			]
		},
		"alcasar": {
			"html": [
				"valoriserdiv5"
			]
		},
		"mirapoint": {
			"html": [
				"\/wm\/mail\/login.html"
			]
		},
		"d-link-network-camera": {
			"html": [
				"<title>dcs-5300"
			]
		},
		"i-gallery": {
			"html": [
				"<title>i-gallery"
			]
		},
		"金山kinggate": {
			"html": [
				"\/src\/system\/login.php"
			]
		},
		"全国烟草系统": {
			"html": [
				"ycportal\/webpublish"
			]
		},
		"h3c icg1000": {
			"html": [
				"<title>icg1000系统管理"
			],
			"implies": [
				"H3C"
			]
		},
		"oa企业智能办公自动化系统": {
			"html": [
				"input name=\"s1\" type=\"image\"",
				"count\/mystat.asp"
			]
		},
		"mdaemon": {
			"html": [
				"\/worldclient.dll?view=main"
			]
		},
		"bloofoxcms": {
			"html": [
				"powered by <a href=\"http:\/\/www.bloofox.com"
			]
		},
		"cmscontrol": {
			"html": [
				"content=\"cmscontrol"
			]
		},
		"webmin": {
			"html": [
				"<title>login to webmin"
			]
		},
		"edk": {
			"html": [
				"<!-- \/killlistable.tpl -->"
			]
		},
		"phpdisk": {
			"html": [
				"powered by phpdisk"
			]
		},
		"北京阳光环球建站系统": {
			"html": [
				"bigsortproduct.asp?bigid"
			]
		},
		"phpmywind": {
			"html": [
				"phpmywind.com all rights reserved"
			]
		},
		"phpdocumentor": {
			"html": [
				"generated by phpdocumentor"
			]
		},
		"clipshare": {
			"html": [
				"powered by <a href=\"http:\/\/www.clip-share.com"
			]
		},
		"calendarscript": {
			"html": [
				"<title>calendar administration : login"
			]
		},
		"escenic": {
			"html": [
				"content=\"escenic"
			]
		},
		"honeywell netaxs": {
			"html": [
				"<title>honeywell netaxs"
			]
		},
		"noalyss": {
			"html": [
				"<title>noalyss"
			]
		},
		"dvr camera": {
			"html": [
				"<title>dvr webclient"
			]
		},
		"nexus_nx_router": {
			"html": [
				"http:\/\/nexuswifi.com\/",
				"<title>nexus nx"
			]
		},
		"vos3000": {
			"html": [
				"<title>vos3000"
			]
		},
		"dircms": {
			"html": [
				"content=\"dircms"
			]
		},
		"fluentnet": {
			"html": [
				"content=\"fluent"
			]
		},
		"twcms": {
			"html": [
				"\/twcms\/theme\/"
			]
		},
		"easylink-web-solutions": {
			"html": [
				"content=\"easylink"
			]
		},
		"arab-portal": {
			"html": [
				"powered by: arab"
			]
		},
		"育友软件": {
			"html": [
				"http:\/\/www.yuysoft.com\/"
			]
		},
		"cisco_cable_modem": {
			"html": [
				"<title>cisco cable modem"
			]
		},
		"h3c er3260g2": {
			"html": [
				"<title>er3260g2系统管理"
			],
			"implies": [
				"H3C"
			]
		},
		"h3c er3260": {
			"html": [
				"<title>er3260系统管理"
			],
			"implies": [
				"H3C"
			]
		},
		"opencms": {
			"html": [
				"powered by opencms"
			]
		},
		"佳能网络摄像头(canon network cameras)": {
			"html": [
				"\/viewer\/live\/en\/live.html"
			]
		},
		"cms-webmanager-pro": {
			"html": [
				"href=\"http:\/\/webmanager-pro.com\">web.manager"
			]
		},
		"brother-printer": {
			"html": [
				"<img src=\"\/common\/image\/hl4040cn"
			]
		},
		"puppet_node_manager": {
			"html": [
				"<title>puppet node manager"
			]
		},
		"diferior": {
			"html": [
				"powered by diferior"
			]
		},
		"iceshop": {
			"html": [
				"powered by iceshop"
			]
		},
		"易瑞授权访问系统": {
			"html": [
				"fe0174bb-f093-42af-ab20-7ec621d10488"
			]
		},
		"guppy": {
			"html": [
				"content=\"guppy"
			]
		},
		"h3c icg 1000": {
			"html": [
				"<title>icg 1000系统管理"
			],
			"implies": [
				"H3C"
			]
		},
		"天融信网络卫士过滤网关": {
			"html": [
				"<title>天融信网络卫士过滤网关"
			]
		},
		"天融信入侵防御系统topidp": {
			"html": [
				"天融信入侵防御系统topidp"
			]
		},
		"barracuda-spam-firewall": {
			"html": [
				"<title>barracuda spam & virus firewall: welcome"
			]
		},
		"fluid-dynamics-search-engine": {
			"html": [
				"content=\"fluid dynamics"
			]
		},
		"drugpak": {
			"html": [
				"powered by drugpak"
			]
		},
		"axous": {
			"html": [
				"title=\"axous shareware shop"
			]
		},
		"78oa": {
			"html": [
				"<title>78oa"
			]
		},
		"easypanel": {
			"html": [
				"\/vhost\/view\/default\/style\/login.css"
			]
		},
		"webedition": {
			"html": [
				"generator\" content=\"webedition"
			]
		},
		"管理易": {
			"html": [
				"管理易",
				"minierp"
			]
		},
		"海盗云商(haidao)": {
			"html": [
				"haidao.web.general.js"
			]
		},
		"nvdvr": {
			"html": [
				"<title>xwebplay"
			]
		},
		"arris-touchstone-router": {
			"html": [
				"\/arris_style.css"
			]
		},
		"siteengine": {
			"html": [
				"content=\"boka siteengine"
			]
		},
		"avantfax": {
			"html": [
				"images\/avantfax-big.png"
			]
		},
		"acsno网络探针": {
			"html": [
				"<title>探针管理与测试系统-登录界面"
			]
		},
		"foxycart": {
			"html": [
				"<script src=\"\/\/cdn.foxycart.com"
			]
		},
		"solr": {
			"html": [
				"<title>solr admin"
			]
		},
		"flyspray": {
			"html": [
				"powered by flyspray"
			]
		},
		"spammark邮件信息安全网关": {
			"html": [
				"<title>spammark邮件信息安全网关"
			]
		},
		"richmail": {
			"html": [
				"<title>richmail"
			]
		},
		"frogcms": {
			"html": [
				"target=\"_blank\">frog cms"
			]
		},
		"dd-wrt": {
			"html": [
				"style\/pwc\/ddwrt.css"
			]
		},
		"am4ss": {
			"html": [
				"powered by am4ss"
			]
		},
		"TerraMaster": {
			"html": [
				"<title>tos loading",
				"<title>terramaster"
			]
		},
		"爱快流控路由": {
			"html": [
				"<title>爱快",
				"\/resources\/images\/land_prompt_ico01.gif"
			]
		},
		"bugfree": {
			"html": [
				"<title>bugfree"
			]
		},
		"fastly cdn": {
			"html": [
				"fastcdn.org"
			]
		},
		"edvr": {
			"html": [
				"<title>edvs\/edvr"
			]
		},
		"浪潮政务系统": {
			"html": [
				"<title>浪潮政务"
			]
		},
		"护卫神网站安全系统": {
			"html": [
				"<title>护卫神.网站安全系统"
			]
		},
		"pretsashop": {
			"html": [
				"content=\"prestashop\""
			]
		},
		"swagger ui": {
			"html": [
				"swagger ui"
			]
		},
		"douphp": {
			"html": [
				"powered by douphp"
			]
		},
		"amaya": {
			"html": [
				"generator\" content=\"amaya"
			]
		},
		"orientdb": {
			"html": [
				"<title>redirecting to orientdb"
			]
		},
		"beecms": {
			"html": [
				"template\/default\/images\/slides.min.jquery.js"
			]
		},
		"eagleeyescctv": {
			"html": [
				"ip surveillance for your life"
			]
		},
		"glfusion": {
			"html": [
				"by <a href=\"http:\/\/www.glfusion.org\/"
			]
		},
		"advantech-webaccess": {
			"html": [
				"\/bw_templete1.dwt"
			]
		},
		"yonyou-erp-nc": {
			"html": [
				"<title>用友新世纪"
			]
		},
		"anygate": {
			"html": [
				"<title>anygate"
			]
		},
		"i@report": {
			"html": [
				"ireportclient"
			]
		},
		"phpweb": {
			"html": [
				"pdv_pagename"
			]
		},
		"getsimple": {
			"html": [
				"powered by getsimple"
			]
		},
		"phpvod": {
			"html": [
				"powered by phpvod"
			]
		},
		"honeywell ip-camera": {
			"html": [
				"<title>honeywell ip-camera"
			]
		},
		"瑞友天翼_应用虚拟化系统 ": {
			"html": [
				"<title>瑞友天翼－应用虚拟化系统"
			]
		},
		"file-upload-manager": {
			"html": [
				"<title>file upload manager"
			]
		},
		"h3c er2100n": {
			"html": [
				"<title>er2100n系统管理"
			],
			"implies": [
				"H3C"
			]
		},
		"belkin-modem": {
			"html": [
				"content=\"belkin"
			]
		},
		"momocms": {
			"html": [
				"powered by momocms"
			]
		},
		"dolibarr": {
			"html": [
				"dolibarr development team"
			]
		},
		"gridsite": {
			"html": [
				"gridsite-admin.cgi?cmd"
			]
		},
		"cauposhop-classic": {
			"html": [
				"powered by cauposhop"
			]
		},
		"xoops": {
			"html": [
				"include\/xoops.js"
			]
		},
		"sugon_gridview": {
			"html": [
				"\/common\/resources\/images\/common\/app\/gridview.ico"
			]
		},
		"mercurial": {
			"html": [
				"<title>mercurial repositories index"
			]
		},
		"hycus-cms": {
			"html": [
				"powered by <a href=\"http:\/\/www.hycus.com"
			]
		},
		"coppermine": {
			"html": [
				"<!--coppermine photo gallery"
			]
		},
		"天融信web应用防火墙": {
			"html": [
				"<title>天融信web应用防火墙"
			]
		},
		"yidacms": {
			"html": [
				"yidacms.css"
			]
		},
		"esotalk": {
			"html": [
				"powered by esotalk"
			]
		},
		"igenus邮件系统": {
			"html": [
				"<title>igenus webmail"
			]
		},
		"h3c er5100": {
			"html": [
				"<title>er5100系统管理"
			],
			"implies": [
				"H3C"
			]
		},
		"易普拉格科研管理系统": {
			"html": [
				"科研管理系统，北京易普拉格科技"
			]
		},
		"bmc-remedy": {
			"html": [
				"<title>remedy mid tier"
			]
		},
		"北创图书检索系统": {
			"html": [
				"opac_two"
			]
		},
		"foosun": {
			"html": [
				"powered by www.foosun.net,products:foosun content manage system"
			]
		},
		"hesk": {
			"html": [
				"powered by <a href=\"https:\/\/www.hesk.com"
			]
		},
		"天融信脆弱性扫描与管理系统": {
			"html": [
				"<title>天融信脆弱性扫描与管理系统"
			]
		},
		"信达oa": {
			"html": [
				"北京创信达科技有限公司"
			]
		},
		"wecenter": {
			"html": [
				"wecenter"
			]
		},
		"juniper-netscreen-secure-access": {
			"html": [
				"\/dana-na\/auth\/welcome.cgi"
			]
		},
		"impresspages-cms": {
			"html": [
				"content=\"impresspages cms"
			]
		},
		"bigdump": {
			"html": [
				"<title>bigdump"
			]
		},
		"360webfacil_360webmanager": {
			"html": [
				"360webmanager software"
			]
		},
		"mongodb": {
			"html": [
				"<a href=\"\/_replset\">replica set status<\/a><\/p>"
			]
		},
		"jeecms": {
			"html": [
				"<title>powered by jeecms"
			]
		},
		"contrexx-cms": {
			"html": [
				"powered by contrexx"
			]
		},
		"phpmoadmin": {
			"html": [
				"<title>phpmoadmin"
			]
		},
		"创星伟业校园网群": {
			"html": [
				"javascripts\/float.js",
				"vcxvcxv"
			]
		},
		"bit-service": {
			"html": [
				"xmlpzs\/webissue.asp"
			]
		},
		"nsfocus_waf": {
			"html": [
				"<title>waf nsfocus",
				"\/images\/logo\/nsfocus.png"
			]
		},
		"shopbuilder": {
			"html": [
				"shopbuilder版权所有"
			]
		},
		"huawei b683v": {
			"html": [
				"<title>huawei b683v"
			]
		},
		"h3c er3200": {
			"html": [
				"<title>er3200系统管理"
			],
			"implies": [
				"H3C"
			]
		},
		"atmail-webmail": {
			"html": [
				"powered by atmail"
			]
		},
		"eazycms": {
			"html": [
				"powered by eazycms"
			]
		},
		"huawei_auth_server": {
			"html": [
				"75718c9a-f029-11d1-a1ac-00c04fb6c223"
			]
		},
		"亿赛通dlp": {
			"html": [
				"cdgserver3"
			]
		},
		"农友政务系统": {
			"html": [
				"1207044504"
			]
		},
		"kayako-supportsuite": {
			"html": [
				"powered by kayako esupport"
			]
		},
		"verizon_router": {
			"html": [
				"<title>verizon router"
			]
		},
		"主机宝": {
			"html": [
				"您访问的是主机宝服务器默认页"
			]
		},
		"festos": {
			"html": [
				"title=\"festos"
			]
		},
		"cemis": {
			"html": [
				"<div id=\"demo\" style=\"overflow:hidden",
				"<title>综合项目管理系统登录"
			]
		},
		"splunk": {
			"html": [
				"splunk.util.normalizeboolean"
			]
		},
		"天融信日志收集与分析系统": {
			"html": [
				"<title>天融信日志收集与分析系统"
			]
		},
		"teamportal": {
			"html": [
				"ts_expiredurl"
			]
		},
		"dbhcms": {
			"html": [
				"powered by dbhcms"
			]
		},
		"formmail": {
			"html": [
				"href=\"http:\/\/www.worldwidemart.com\/scripts\/formmail.shtml"
			]
		},
		"filevista": {
			"html": [
				"welcome to filevista"
			]
		},
		"huawei csp": {
			"html": [
				"<title>huawei csp"
			]
		},
		"somoidea": {
			"html": [
				"design by somoidea"
			]
		},
		"mikrotik": {
			"html": [
				"<title>routeros",
				"mikrotik"
			]
		},
		"verizon_wireless_router": {
			"html": [
				"<title>wireless broadband router management console",
				"verizon_logo_blk.gif"
			]
		},
		"cmsqlite": {
			"html": [
				"powered by cmsqlite"
			]
		},
		"天融信 topad": {
			"html": [
				"<title>天融信 topad"
			]
		},
		"doccms": {
			"html": [
				"power by doccms"
			]
		},
		"dota-openstats": {
			"html": [
				"content=\"openstats.iz.rs"
			]
		},
		"ischoolsite": {
			"html": [
				"powered by <a href=\"http:\/\/www.ischoolsite.com"
			]
		},
		"08cms": {
			"html": [
				"typeof(_08cms)"
			]
		},
		"bulletlink-newspaper-template": {
			"html": [
				"powered by bulletlink"
			]
		},
		"lemis管理系统": {
			"html": [
				"lemis.web_app_name"
			]
		},
		"storm": {
			"html": [
				"<title>storm ui"
			]
		},
		"inout-adserver": {
			"html": [
				"powered by inoutscripts"
			]
		},
		"泰信tmailer邮件系统": {
			"html": [
				"<title>tmailer"
			]
		},
		"holocms": {
			"html": [
				"powered by holocms"
			]
		},
		"jamroom": {
			"html": [
				"content=\"talldude networks"
			]
		},
		"glossword": {
			"html": [
				"content=\"glossword"
			]
		},
		"huawei espace 7910": {
			"html": [
				"<title>huawei espace 7910"
			]
		},
		"axis2-web": {
			"html": [
				"axis2-web\/css\/axis-style.css"
			]
		},
		"maticsoft_shop_动软商城": {
			"html": [
				"maticsoft shop"
			]
		},
		"深信服防火墙类产品": {
			"html": [
				"sangfor fw"
			]
		},
		"mallbuilder": {
			"html": [
				"powered by mallbuilder"
			]
		},
		"ecomat-cms": {
			"html": [
				"content=\"ecomat cms"
			]
		},
		"bxemail": {
			"html": [
				"<title>百讯安全邮件系统"
			]
		},
		"网动云视讯平台": {
			"html": [
				"<title>acenter"
			]
		},
		"videoiq camera": {
			"html": [
				"<title>videoiq camera login"
			]
		},
		"appserv": {
			"html": [
				"index.php?appservlang=th"
			]
		},
		"苏亚星校园管理系统": {
			"html": [
				"\/ws2004\/public\/"
			]
		},
		"fcms": {
			"html": [
				"powered by family connections"
			]
		},
		"mixcall座席管理中心": {
			"html": [
				"<title>mixcall座席管理中心"
			]
		},
		"百为智能流控路由器": {
			"html": [
				"<title>bytevalue 智能流控路由器",
				"<a href=\"http:\/\/www.bytevalue.com\/\" target=\"_blank\">"
			]
		},
		"kleeja": {
			"html": [
				"powered by kleeja"
			]
		},
		"天融信web应用安全防护系统": {
			"html": [
				"<title>天融信web应用安全防护系统"
			]
		},
		"ioncube-loader": {
			"html": [
				"alt=\"ioncube logo"
			]
		},
		"mantis": {
			"html": [
				"mantisbt team"
			]
		},
		"北京金盘鹏图软件": {
			"html": [
				"speakintertscarch.aspx"
			]
		},
		"axis-network-camera": {
			"html": [
				"<title>axis video server"
			]
		},
		"ispconfig": {
			"html": [
				"powered by <a href=\"http:\/\/www.ispconfig.org"
			]
		},
		"gpsgate-server": {
			"html": [
				"<title>gpsgate server - "
			]
		},
		"易企cms": {
			"html": [
				"content=\"yiqicms"
			]
		},
		"dasannetworks": {
			"html": [
				"clear_cookie(\"login\");"
			]
		},
		"symantec messaging gateway": {
			"html": [
				"<title>messaging gateway"
			]
		},
		"hims酒店云计算服务": {
			"html": [
				"hims酒店云计算服务"
			]
		},
		"天融信ads管理平台": {
			"html": [
				"<title>天融信ads管理平台"
			]
		},
		"悟空crm": {
			"html": [
				"<title>悟空crm"
			]
		},
		"alstrasoft-epay-enterprise": {
			"html": [
				"powered by epay enterprise"
			]
		},
		"协众oa": {
			"html": [
				"powered by cnoa.cn"
			]
		},
		"sltm32_configuration": {
			"html": [
				"<title>sltm32 web configuration pages "
			]
		},
		"clipbucket": {
			"html": [
				"href=\"http:\/\/clip-bucket.com\/\">clipbucket"
			]
		},
		"campsite": {
			"html": [
				"content=\"campsite"
			]
		},
		"i-o-data-router": {
			"html": [
				"<title>i-o data wireless broadband router"
			]
		},
		"Hikvision": {
			"headers": {
				"server": "dnvrs-webs"
			},
			"html": [
				"g_szcachetime",
				"\/doc\/page\/login.asp"
			]
		},
		"deluxebb": {
			"html": [
				"content=\"powered by deluxebb"
			]
		},
		"1024 cms": {
			"html": [
				"powered by 1024 cms"
			]
		},
		"锐商企业cms": {
			"html": [
				"href=\"\/writable\/clientimages\/mycss.css"
			]
		},
		"aicart": {
			"html": [
				"app_authenticate"
			]
		},
		"kandidat-cms": {
			"html": [
				"content=\"kandidat-cms"
			]
		},
		"汉码软件": {
			"html": [
				"<title>汉码软件"
			]
		},
		"jcow": {
			"html": [
				"end jcow_application_box"
			]
		},
		"comersuscart": {
			"html": [
				"href=\"comersus_showcart.asp"
			]
		},
		"某通用型政府cms": {
			"html": [
				"\/deptwebsiteaction.do"
			]
		},
		"upupw": {
			"html": [
				"<title>upupw环境集成包"
			]
		},
		"openmas": {
			"html": [
				"<title>openmas"
			]
		},
		"正方oa": {
			"html": [
				"zfoausername"
			]
		},
		"cgi:irc": {
			"html": [
				"<title>cgi:irc login"
			]
		},
		"siemens_simatic": {
			"html": [
				"\/s7web.css"
			]
		},
		"gallarific": {
			"html": [
				"<title>gallarific > sign in"
			]
		},
		"siemens ip cameras": {
			"html": [
				"<title>siemens ip camera"
			]
		},
		"thinkox": {
			"html": [
				"<title>thinkox"
			]
		},
		"cmstop": {
			"html": [
				"cmstop-list-text.css"
			]
		},
		"gossamer-forum": {
			"html": [
				"<title>gossamer forum"
			]
		},
		"单点crm系统": {
			"html": [
				"<title>客户关系管理-crm"
			]
		},
		"ruckus": {
			"html": [
				"<title>ruckus wireless admin"
			]
		},
		"中国期刊先知网": {
			"html": [
				"本系统由<span class=\"style1\" ><a href=\"http:\/\/www.firstknow.cn"
			]
		},
		"帝国empirecms": {
			"html": [
				"<title>powered by empirecms"
			]
		},
		"华为 netopen": {
			"html": [
				"<title>huawei netopen system"
			]
		},
		"ezcms": {
			"html": [
				"powered by ezcms"
			]
		},
		"微门户": {
			"html": [
				"\/tpl\/home\/weimeng\/common\/css\/"
			]
		},
		"蓝凌eis智慧协同平台": {
			"html": [
				"v11_qrcodebar clr"
			]
		},
		"tutucms": {
			"html": [
				"tutucms\""
			]
		},
		"fortinet firewall": {
			"html": [
				"<title>firewall notification"
			]
		},
		"pageadmin": {
			"html": [
				"content=\"pageadmin cms\""
			]
		},
		"urp教务系统": {
			"html": [
				"<title>urp 综合教务系统"
			]
		},
		"esyndicat": {
			"html": [
				"content=\"esyndicat"
			]
		},
		"fluxbb": {
			"html": [
				"powered by <a href=\"http:\/\/fluxbb.org\/"
			]
		},
		"h3c er8300": {
			"html": [
				"<title>er8300系统管理"
			],
			"implies": [
				"H3C"
			]
		},
		"entrans": {
			"html": [
				"<title>entrans"
			]
		},
		"easytrace(botwave)": {
			"html": [
				"<title>easytrace"
			]
		},
		"171cms": {
			"html": [
				"<title>171cms"
			]
		},
		"taocms": {
			"html": [
				">taocms<"
			]
		},
		"srun3000计费认证系统": {
			"html": [
				"<title>srun3000"
			]
		},
		"易分析": {
			"html": [
				"<title>易分析 phpstat analytics"
			]
		},
		"custom-cms": {
			"html": [
				"title=\"powered by ccms"
			]
		},
		"mvb2000": {
			"html": [
				"<title>mvb2000"
			]
		},
		"daffodil-crm": {
			"html": [
				"powered by daffodil"
			]
		},
		"phpems考试系统": {
			"html": [
				"<title>phpems"
			]
		},
		"comcast_business_gateway": {
			"html": [
				"comcast business gateway"
			]
		},
		"2z project": {
			"html": [
				"generator\" content=\"2z project"
			]
		},
		"iscripts-multicart": {
			"html": [
				"powered by <a href=\"http:\/\/iscripts.com\/multicart"
			]
		},
		"dvwa": {
			"html": [
				"<title>damn vulnerable web app (dvwa) - login"
			]
		},
		"netshare_vpn": {
			"html": [
				"<title>netshare",
				"<title>vpn"
			]
		},
		"opensns": {
			"html": [
				"content=\"opensns"
			]
		},
		"擎天电子政务": {
			"html": [
				"window.location = \"homepages\/index.aspx"
			]
		},
		"mvmmall": {
			"html": [
				"content=\"mvmmall"
			]
		},
		"绿盟下一代防火墙": {
			"html": [
				"<title>nsfocus nf"
			]
		},
		"aurion": {
			"html": [
				"<!-- aurion teal will be used as the login-time default"
			]
		},
		"dmxready-portfolio-manager": {
			"html": [
				"rememberme_portfoliomanager"
			]
		},
		"kloxo-single-server": {
			"html": [
				"<title>hypervm"
			]
		},
		"tpshop": {
			"html": [
				"<script src=\"\/public\/js\/global.js\"><\/script>"
			]
		},
		"easyconsole-cms": {
			"html": [
				"powered by easyconsole cms"
			]
		},
		"auxilium-petratepro": {
			"html": [
				"index.php?cmd=11"
			]
		},
		"25yi": {
			"html": [
				"powered by 25yi"
			]
		},
		"h3c er5200g2": {
			"html": [
				"<title>er5200g2系统管理"
			],
			"implies": [
				"H3C"
			]
		},
		"maccms": {
			"html": [
				"maccms:voddaycount",
				"maccms.la"
			]
		},
		"ucstar": {
			"html": [
				"<title>ucstar 管理控制台"
			]
		},
		"nitc": {
			"html": [
				"nitc web marketing service"
			]
		},
		"censura": {
			"html": [
				"powered by: <a href=\"http:\/\/www.censura.info"
			]
		},
		"南方数据": {
			"html": [
				"content=\"copyright 2003-2015 - southidc.net"
			]
		},
		"wp plugin all-in-one-seo-pack": {
			"html": [
				"<!-- \/all in one seo pack -->"
			]
		},
		"tccms": {
			"html": [
				"<title>power by tccms"
			]
		},
		"emeeting-online-dating-software": {
			"html": [
				"emeeting dating software"
			]
		},
		"cisco_epc3925": {
			"html": [
				"docsis_system",
				"epc3925"
			]
		},
		"cachelogic-expired-domains-script": {
			"html": [
				"href=\"http:\/\/cachelogic.net\">cachelogic.net"
			]
		},
		"科蚁cms": {
			"html": [
				"powered by <a href=\"http:\/\/www.keyicms.com"
			]
		},
		"esvon-classifieds": {
			"html": [
				"powered by esvon"
			]
		},
		"panabit智能网关": {
			"html": [
				"<title>panabit"
			]
		},
		"npoint": {
			"html": [
				"<title>powered by npoint"
			]
		},
		"turbocms": {
			"html": [
				"powered by turbocms"
			]
		},
		"护卫神主机管理": {
			"html": [
				"<title>护卫神·主机管理系统"
			]
		},
		"合正网站群内容管理系统": {
			"html": [
				"网站群内容管理系统"
			]
		},
		"qno_router": {
			"html": [
				"\/qnovirtual_keyboard.js",
				"\/images\/login_img01_03.gif"
			]
		},
		"geoserver": {
			"html": [
				"class=\"geoserver lebeg"
			]
		},
		"milu_seotool": {
			"html": [
				"plugin.php?id=milu_seotool"
			]
		},
		"cafeengine": {
			"html": [
				"<a href=http:\/\/cafeengine.com>cafeengine.com"
			]
		},
		"浪潮服务器ipmi管理口": {
			"html": [
				"img\/inspur_logo.png"
			]
		},
		"xheditor": {
			"html": [
				"xheditor_lang\/zh-cn.js"
			]
		},
		"freenas": {
			"html": [
				"title=\"welcome to freenas"
			]
		},
		"网易企业邮箱": {
			"html": [
				"frmvalidator",
				"<title>邮箱用户登录"
			]
		},
		"php云": {
			"html": [
				"<div class=\"index_link_list_name\">"
			]
		},
		"6kbbs": {
			"html": [
				"powered by 6kbbs"
			]
		},
		"dotcms": {
			"html": [
				"\/index.dot"
			]
		},
		"achecker web accessibility evaluation tool": {
			"html": [
				"<title>checker : web accessibility checker"
			]
		},
		"网御上网行为管理系统": {
			"html": [
				"<title>leadsec acm"
			]
		},
		"wdcp管理系统": {
			"html": [
				"<title>wdcp服务器"
			]
		},
		"dell-printer": {
			"html": [
				"<title>dell laser printer"
			]
		},
		"buddy-zone": {
			"html": [
				"powered by <a href=\"http:\/\/www.vastal.com"
			]
		},
		"energine": {
			"html": [
				"stylesheets\/energine.css"
			]
		},
		"cisco ucm": {
			"html": [
				"<title>cisco unified"
			]
		},
		"金和协同管理平台": {
			"html": [
				"<title>金和协同管理平台"
			]
		},
		"hp-storageworks-library": {
			"html": [
				"<title>hp storageworks"
			]
		},
		"360企业版": {
			"html": [
				"360entinst"
			]
		},
		"apache-archiva": {
			"html": [
				"<title>apache archiva"
			]
		},
		"adiscon_loganalyzer": {
			"html": [
				"<title>adiscon loganalyzer"
			]
		},
		"bm-classifieds": {
			"html": [
				"<!-- start header table - holds graphic and site name -->"
			]
		},
		"wamp": {
			"html": [
				"<title>wampserver"
			]
		},
		"citrix-metaframe": {
			"html": [
				"window.location=\"\/citrix\/metaframe"
			],
			"implies": [
				"Citrix"
			]
		},
		"boyowcms": {
			"html": [
				"publish by boyowcms"
			]
		},
		"bluequartz": {
			"html": [
				"<title>login - bluequartz"
			]
		},
		"lepton-cms": {
			"html": [
				"powered by lepton cms"
			]
		},
		"hotaru-cms": {
			"html": [
				"content=\"hotaru"
			]
		},
		"locus_solarnoc": {
			"html": [
				"<title>solarnoc - login"
			]
		},
		"jieqi cms": {
			"html": [
				"<title>jieqi cms"
			]
		},
		"致远OA M3 Server": {
			"html": [
				"<title>m3 server<\/title>"
			]
		},
		"致远OA M1 Server": {
			"html": [
				"<title>m1-server<\/title>"
			]
		},
		"红帆-ioffice OA": {
			"html": [
				"<title>ioffice.net<\/title>"
			]
		},
		"微三云管理系统": {
			"html": [
				"管理系统 management system"
			]
		},
		"Swagger UI": {
			"html": [
				"swagger ui"
			]
		},
		"Ruijie": {
			"html": [
				"4008 111 000",
				"url=\/cgi-bin\/mcfi",
				"<title>rg-uac登录页面"
			]
		},
		"Huawei SMC": {
			"html": [
				"script\/smcscript.js?version="
			]
		},
		"H3C Router": {
			"html": [
				"\/wnm\/ssl\/web\/frame\/login.html"
			],
			"implies": [
				"H3C"
			]
		},
		"Cisco SSLVPN": {
			"html": [
				"\/+cscoe+\/logon.html"
			]
		},
		"Airflow": {
			"html": [
				"<title>airflow"
			]
		},
		"CoreMail": {
			"html": [
				"<script type=\"text/javascript\" src=\"\/coremail\/common"
			]
		},
		"DouPHP": {
			"html": [
				"powered by douphp"
			]
		},
		"yonyou-NC": {
			"html": [
				"logo\/images\/ufida_nc.png",
				"用友nc"
			]
		},
		"RabbitMQ": {
			"html": [
				"<title>rabbitmq management<\/title>"
			]
		},
		"联软准入": {
			"html": [
				"网络准入"
			]
		},
		"列目录": {
			"html": [
				"index of \/",
				" - \/<\/title>"
			]
		},
		"RegentApi_v2.0": {
			"html": [
				"regentapi_v2.0"
			]
		},
		"深信服WEB防篡改管理系统": {
			"html": [
				"web防篡改",
				"cgi-bin\/tamper_admin.cgi"
			]
		},
		"YApi": {
			"html": [
				"id=\"yapi\""
			]
		},
		"WeiPHP": {
			"html": [
				"weiphp.css",
				"content=\"weiphp"
			]
		},
		"Nagio": {
			"html": [
				"nagiosxi"
			]
		},
		"群晖 NAS": {
			"html": [
				"synology"
			]
		},
		"山石网科 防火墙": {
			"html": [
				"hillstone",
				"licenseaggrement"
			]
		},
		"360天堤新一代智慧防火墙": {
			"html": [
				"360天堤",
				"360防火墙"
			]
		},
		"360网神防火墙系统": {
			"html": [
				"网神防火墙系统"
			]
		},
		"网神SecGate 3600防火墙": {
			"html": [
				"网神secgate",
				"3600防火墙"
			]
		},
		"蓝盾防火墙": {
			"html": [
				"蓝盾"
			]
		},
		"LanProxy": {
			"html": [
				"lanproxy",
				"lanproxy-config"
			]
		},
		"ManageEngine ADManager Plus": {
			"html": [
				"hashtable.js",
				"manageengine"
			]
		},
		"phpshe 商城系统": {
			"html": [
				"powered by phpshe"
			]
		},
		"Grafana": {
			"html": [
				"grafana",
				"grafana-app"
			]
		},
		"中新金盾信息安全管理系统": {
			"html": [
				"中新金盾信息安全管理系统"
			]
		},
		"VMware-vCenter": {
			"html": [
				"vmware",
				"id_visdk"
			]
		},
		"AWS S3 Bucket": {
			"html": [
				"invalidbucketname",
				"aliyuncs"
			]
		},
		"网心云设备": {
			"html": [
				"网心云设备"
			]
		},
		"Webmin": {
			"html": [
				"webmin"
			]
		},
		"蜂网企业流控云路由器": {
			"html": [
				"企业级流控云路由器"
			]
		},
		"网御 安全网关": {
			"html": [
				"网御星云"
			]
		},
		"Citrix Access Gateway": {
			"html": [
				"citrix access gateway"
			],
			"implies": [
				"Citrix"
			]
		},
		"深信服安全感知平台": {
			"html": [
				"安全感知平台"
			]
		},
		"FineReport": {
			"html": [
				"reportserver",
				"=fs"
			]
		},
		"CAS单点登录": {
			"html": [
				"central authentication service",
				"cas\/login"
			]
		},
		"海康威视流媒体管理服务器": {
			"html": [
				"流媒体管理服务器"
			]
		},
		"阿里巴巴otter manager": {
			"html": [
				"otter manager",
				"channellist"
			]
		},
		"VMware-vRealize": {
			"html": [
				"vrealize",
				"identity manager"
			]
		},
		"安恒云堡垒机": {
			"html": [
				"dbappsecurity",
				"安恒云堡垒机"
			]
		},
		"协众OA": {
			"html": [
				"scripts\/cnoa.extra.js"
			]
		},
		"FastAdmin": {
			"html": [
				"fastadmin"
			]
		},
		"imo云办公室": {
			"html": [
				"<a title=\"imo云办公室\"",
				"高效率网上办公平台",
				"imo_setup.exe"
			]
		},
		"永中DCS": {
			"html": [
				"<title>永中文档在线预览dcs<\/title>",
				"www.yozodcs.com"
			]
		},
		"JeecgBoot": {
			"html": [
				"jeecgboot",
				"polyfill_"
			]
		},
		"帆软数据决策系统": {
			"html": [
				">数据决策系统",
				"reportserver?op"
			]
		},
		"金山TimeOn云杀毒": {
			"html": [
				"<title>timeon",
				"iepngfix\/iepngfix_tilebg.js"
			]
		},
		"金山终端安全": {
			"html": [
				"setup\/kanclient.exe",
				"iepngfix\/iepngfix_tilebg.js"
			],
			"implies": [
				"kingsoft"
			]
		},
		"微擎 - 公众平台自助引擎": {
			"html": [
				"微擎 - 公众平台自助引擎",
				"www.w7.cc"
			]
		},
		"Jspxcms": {
			"html": [
				"- powered by jspxcms"
			]
		},
		"金合OA": {
			"html": [
				"jhsoft.web.login"
			]
		},
		"好视通视频会议系统": {
			"html": [
				"login\/createqrcode.do"
			]
		},
		"ueditor": {
			"html": [
				"ueditor.all.js",
				"ue.geteditor"
			]
		},
		"蓝凌EIS智慧协同平台": {
			"html": [
				"\/scripts\/jquery.landray.common.js",
				"蓝凌软件"
			]
		},
		"Hue 大数据框架": {
			"html": [
				"welcome to hue"
			]
		},
		"亿邮邮件系统": {
			"html": [
				"eyou.net"
			]
		},
		"网神下一代极速防火墙": {
			"html": [
				"网神信息技术"
			]
		},
		"中腾OA": {
			"html": [
				"zt_webframe"
			]
		},
		"新软科技-极通EWEBS": {
			"html": [
				"clientdownload.xgi"
			]
		},
		"华天动力OA": {
			"html": [
				"oaapp\/webobjects\/oaapp.woa"
			]
		},
		"JEECMS": {
			"html": [
				"\/r\/cms\/www"
			]
		},
		"Hadoop": {
			"html": [
				"static\/hadoop-st.png"
			]
		},
		"H3C Web网管": {
			"html": [
				"web网管用户登录"
			],
			"implies": [
				"H3C"
			]
		},
		"H3C ER6300G2": {
			"html": [
				"er6300g2",
				"h3c.com"
			],
			"implies": [
				"H3C"
			]
		},
		"H3C ER3100": {
			"html": [
				"er3100",
				"h3c.com"
			],
			"implies": [
				"H3C"
			]
		},
		"锐捷 SSLVPN": {
			"html": [
				"rjweb",
				"rjsslvpn_encookie"
			]
		},
		"天迈科技网络视频监控系统": {
			"html": [
				"天迈科技",
				"网络视频监控系统"
			]
		},
		"MinIO": {
			"html": [
				"<title>minio browser<\/title>"
			]
		},
		"Consul by HashiCorp": {
			"html": [
				"<title>consul<\/title>"
			]
		},
		"明源云ERP": {
			"html": [
				"<title>明源云erp<\/title>"
			]
		}
	}
}
`
