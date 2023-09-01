package spider

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"github.com/antchfx/htmlquery"
	"github.com/chromedp/cdproto/page"
	"github.com/chromedp/chromedp"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/text/encoding/simplifiedchinese"
	"io/ioutil"
	"log"
	"math/big"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

type PocWebAppData struct {
	Title          string `json:"title"`           //网站标题
	Link           string `json:"link"`            //网站链接
	StatusCode     string `json:"status_code"`     //状态代码
	Ip             string `json:"ip"`              //ip
	Port           string `json:"port"`            //端口
	Keywords       string `json:"keywords"`        //关键字
	Description    string `json:"description"`     //网站描述
	Classification string `json:"classification"`  //内容分类
	SensitiveWords string `json:"sensitive_words"` //敏感词
	Framework      string `json:"framework"`       //网站框架
	Header         string `json:"header"`          //头部信息
	SecondaryLinks string `json:"secondary_links"` //二级链接
	LargeImage     string `json:"large_image"`     //网站截图（大图）
	SmallImage     string `json:"small_image"`     //网站截图（封面）
	Tls            string `json:"tls"`             //tls证书
}

type Org struct {
	Country            string `json:"country"`             // 国家或地区
	Province           string `json:"province"`            // 省/市/自治区
	Locality           string `json:"locality"`            // 所在地
	OrganizationalUnit string `json:"organizational_unit"` // 组织单位
	Organization       string `json:"organization"`        // 组织
	CommonName         string `json:"common_name"`         // 常用名称
	StreetAddress      string `json:"street_address"`      // 街道地址
	PostalCode         string `json:"postal_code"`         // 邮政编码
}

type TLS struct {
	Proto                 string      `json:"proto"`                   // 协议
	Subject               Org         `json:"subject"`                 // 主题名称
	Issuer                Org         `json:"issuer"`                  // 签发者名称
	DNSNames              []string    `json:"dns_names"`               // DNS服务器名称
	CRLDistributionPoints string      `json:"crl_distribution_points"` // CRL分发点 URI
	OCSPServer            string      `json:"ocsp_server"`             // 在线证书状态协议 URI
	IssuingCertificateURL string      `json:"issuing_certificate_url"` // CA签发者 URI
	SubjectKeyId          []uint8     `json:"subject_key_id"`          // 主题密钥标志符
	AuthorityKeyId        []uint8     `json:"authority_key_id"`        // 授权密钥标志符
	SignatureAlgorithm    string      `json:"signature_algorithm"`     // 签名算法
	PublicKeyAlgorithm    string      `json:"public_key_algorithm"`    // 公钥算法
	Signature             []uint8     `json:"signature"`               // 签名
	PublicKey             interface{} `json:"public_key"`              // 公共密钥
	NotBefore             time.Time   `json:"not_before"`              // 有效期开始
	NotAfter              time.Time   `json:"not_after"`               // 有效期结束
	SerialNumber          *big.Int    `json:"serial_number"`           // 序列号
	Version               int         `json:"version"`                 // 版本
}

const (
	MaxWidth  = 1920
	MinHeight = 1080
)

/*生成UUID*/
func GenerateUUID() string {
	return uuid.NewV4().String()
}

/*
执行截图
--remote-debugging-port=9222
参考：https://github.com/chromedp/chromedp/issues/1131

chromedp.Evaluate(js, &height), 返回最后一行js语句的结果
*/
func DoFullScreenshot(url, path string) bool {
	opts := append(chromedp.DefaultExecAllocatorOptions[:],
		chromedp.NoDefaultBrowserCheck,
		chromedp.Flag("headless", false),
		chromedp.Flag("ignore-certificate-errors", true),
		chromedp.Flag("disable-web-security", true),
		chromedp.Flag("disable-extensions", true), //开启插件支持
		chromedp.Flag("disable-default-apps", true),
		chromedp.Flag("disable-gpu", true), //开启 gpu 渲染
		chromedp.Flag("hide-scrollbars", true),
		chromedp.Flag("mute-audio", true),
		chromedp.Flag("no-sandbox", true),
		chromedp.Flag("no-default-browser-check", true),
		chromedp.NoFirstRun, //设置网站不是首次运行
		chromedp.WindowSize(MaxWidth, MinHeight),
		chromedp.Flag("blink-settings", "imagesEnabled=true"),
		chromedp.Flag("enable-automation", false),
		chromedp.UserAgent("Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/73.0.3683.103 Safari/537.36"),
	)
	allocCtx, cancel := chromedp.NewExecAllocator(context.Background(), opts...)
	defer cancel()

	// 创建chrome实例
	ctx, cancel := chromedp.NewContext(
		allocCtx,
		chromedp.WithLogf(log.Printf),
	)
	defer cancel()

	// 创建超时时间
	ctx, cancel = context.WithTimeout(ctx, 15*time.Second)
	defer cancel()

	// 缓存对象
	var buf []byte

	// 运行截屏
	if err := chromedp.Run(ctx, fullScreenshot(url, 100, &buf)); err != nil {
		return false
	}

	// 保存文件
	if "" != path {
		if err := ioutil.WriteFile(path, buf, 0644); err != nil {
			return false
		}
	}

	return true
}

/*全屏截图*/
func fullScreenshot(url string, quality int64, res *[]byte) chromedp.Tasks {
	return chromedp.Tasks{
		chromedp.Navigate(url),
		chromedp.ActionFunc(func(ctx context.Context) (err error) {
			*res, err = page.CaptureScreenshot().WithQuality(quality).WithClip(&page.Viewport{
				X:      0,
				Y:      0,
				Width:  MaxWidth,
				Height: MinHeight,
				Scale:  1,
			}).Do(ctx)
			if err != nil {
				return err
			}
			return nil
		}),
	}
}

func (a TLS) IsEmpty() bool {
	return reflect.DeepEqual(a, TLS{})
}

// 转化字符集
func ConvertCharset(dataByte []byte) string {
	sourceCode := string(dataByte)
	if !utf8.Valid(dataByte) {
		data, _ := simplifiedchinese.GBK.NewDecoder().Bytes(dataByte)
		sourceCode = string(data)
	}
	return sourceCode
}

func CatchHTTP(url, ip string, port int, timeOut time.Duration) (site PocWebAppData) {

	// 构造GET请求
	request, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return site
	}
	request.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/86.0.4240.198 Safari/537.36")
	// 跳过https验证
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: tr, Timeout: timeOut}
	resp, err := client.Do(request)
	if err != nil {
		return site
	}

	defer resp.Body.Close()

	if resp == nil {
		return site
	}

	if resp.TLS == nil {
		site.Tls = ""
	} else {
		if len(resp.TLS.PeerCertificates) == 0 {
			site.Tls = ""
		} else {
			certInfo := resp.TLS.PeerCertificates[0]
			if certInfo == nil {
				site.Tls = ""
			} else {
				tls := TLS{
					Proto: resp.Proto,
					Subject: Org{
						Country:            strings.Join(certInfo.Subject.Country, ","),
						Province:           strings.Join(certInfo.Subject.Province, ","),
						Locality:           strings.Join(certInfo.Subject.Locality, ","),
						OrganizationalUnit: strings.Join(certInfo.Subject.OrganizationalUnit, ","),
						Organization:       strings.Join(certInfo.Subject.Organization, ","),
						CommonName:         certInfo.Subject.CommonName,
						StreetAddress:      strings.Join(certInfo.Subject.StreetAddress, ","),
						PostalCode:         strings.Join(certInfo.Subject.PostalCode, ","),
					},
					Issuer: Org{
						Country:            strings.Join(certInfo.Issuer.Country, ","),
						Province:           strings.Join(certInfo.Issuer.Province, ","),
						Locality:           strings.Join(certInfo.Issuer.Locality, ","),
						OrganizationalUnit: strings.Join(certInfo.Issuer.OrganizationalUnit, ","),
						Organization:       strings.Join(certInfo.Issuer.Organization, ","),
						CommonName:         certInfo.Issuer.CommonName,
						StreetAddress:      strings.Join(certInfo.Issuer.StreetAddress, ","),
						PostalCode:         strings.Join(certInfo.Issuer.PostalCode, ","),
					},
					DNSNames:              certInfo.DNSNames,
					CRLDistributionPoints: strings.Join(certInfo.CRLDistributionPoints, ","),
					OCSPServer:            strings.Join(certInfo.OCSPServer, ","),
					IssuingCertificateURL: strings.Join(certInfo.IssuingCertificateURL, ","),
					SubjectKeyId:          certInfo.SubjectKeyId,
					AuthorityKeyId:        certInfo.AuthorityKeyId,
					SignatureAlgorithm:    certInfo.SignatureAlgorithm.String(),
					PublicKeyAlgorithm:    certInfo.PublicKeyAlgorithm.String(),
					Signature:             certInfo.Signature,
					PublicKey:             certInfo.PublicKey,
					NotBefore:             certInfo.NotBefore,
					NotAfter:              certInfo.NotAfter,
					SerialNumber:          certInfo.SerialNumber,
					Version:               certInfo.Version,
				}
				tlsStr, err := json.Marshal(tls)
				if err == nil {
					site.Tls = string(tlsStr)
				} else {
					site.Tls = ""
				}
			}
		}
	}

	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err)
		return
	}

	htmlData := strings.NewReader(ConvertCharset(data))

	doc, err := htmlquery.Parse(htmlData)
	if err != nil {
		fmt.Println(err)
		return
	}

	titleNode := htmlquery.FindOne(doc, `//title`)
	if titleNode != nil {
		site.Title = htmlquery.InnerText(titleNode)
	}

	descriptionNode := htmlquery.FindOne(doc, `//meta[@name="description"]`)
	if descriptionNode != nil {
		site.Description = htmlquery.SelectAttr(descriptionNode, "content")
	}

	keywordsNode := htmlquery.FindOne(doc, `//meta[@name="keywords"]`)
	if keywordsNode != nil {
		site.Keywords = htmlquery.SelectAttr(keywordsNode, "content")
	}

	header, _ := json.Marshal(resp.Header)
	site.Header = string(header)
	site.Port = strconv.Itoa(port)
	site.Ip = ip
	site.Classification = ""
	site.Framework = ""
	site.StatusCode = strconv.Itoa(resp.StatusCode)
	site.LargeImage = ""
	site.SmallImage = ""
	site.SensitiveWords = ""
	site.Link = url

	var links []map[string]string

	for _, node := range htmlquery.Find(doc, `//a`) {
		if node != nil {
			_link, _text := "", ""
			nodeLink := htmlquery.FindOne(node, "/@href")
			if nodeLink != nil {
				_link = htmlquery.SelectAttr(nodeLink, "href")
			}
			_text = htmlquery.InnerText(node)
			if _link != "" && _text != "" && _link != "#" {
				links = append(links, map[string]string{
					"link": _link,
					"text": _text,
				})
			}
		}
	}

	linksStr, _ := json.Marshal(links)
	site.SecondaryLinks = string(linksStr)

	siteImageName := fmt.Sprintf(`%s.png`, GenerateUUID())
	status := DoFullScreenshot(url, fmt.Sprintf("./static/%s", siteImageName))
	if status {
		site.SmallImage = siteImageName
		site.LargeImage = siteImageName
	}

	return site
}
