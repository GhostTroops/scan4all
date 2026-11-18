package nuclei_Yaml

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/GhostTroops/scan4all/lib/util"
)

// nuclei 集成入口：
// 兼容 nuclei v2 / v3 的命令行差异（v2 的 -sa 表示 self-contained，v3 的 -sa 表示 scan-all-ips，
// 且 v3 必须显式提供模板路径），并把内嵌在 config 目录中的模板（config/51pwn）作为默认模板来源。

var (
	nucleiCheckOnce sync.Once
	nucleiBin       string
	nucleiRawVer    string
	nucleiMajor     int
)

var reNucleiVersion = regexp.MustCompile(`v(\d+)\.(\d+)\.(\d+)`)

// NucleiInfo 返回 nuclei 可执行文件路径、版本字符串与主版本号
func NucleiInfo() (bin string, version string, major int) {
	nucleiCheckOnce.Do(func() {
		nucleiBin, _ = exec.LookPath("nuclei")
		if "" == nucleiBin {
			return
		}
		// nuclei -version 会输出到 stdout；部分版本输出到 stderr，这里都捕获
		out, _ := exec.Command(nucleiBin, "-version").CombinedOutput()
		nucleiRawVer = strings.TrimSpace(string(out))
		if m := reNucleiVersion.FindStringSubmatch(nucleiRawVer); nil != m {
			nucleiMajor, _ = strconv.Atoi(m[1])
		}
	})
	return nucleiBin, nucleiRawVer, nucleiMajor
}

// NucleiVersion 返回 nuclei 可执行文件的版本描述，未安装时返回空
func NucleiVersion() string {
	_, v, _ := NucleiInfo()
	return v
}

// templatesDir 返回内置 nuclei 模板目录，优先使用运行目录下的 config/51pwn，
// 其次尝试 config/nuclei-templates；都不存在时返回空（交给 nuclei 使用自身默认模板）。
func templatesDir() string {
	candidates := []string{
		filepath.Join(util.SzPwd, "config", "51pwn"),
		filepath.Join(util.SzPwd, "config", "nuclei-templates"),
	}
	for _, szDir := range candidates {
		if fi, err := os.Stat(szDir); nil == err && fi.IsDir() {
			return szDir
		}
	}
	return ""
}

// BuildNucleiArgs 依据 nuclei 版本与运行配置构造命令行参数（不含可执行文件本身）
func BuildNucleiArgs(listFile string, jsonOutput bool) []string {
	_, _, major := NucleiInfo()
	args := []string{"-duc", "-silent", "-nc"}
	szTpl := templatesDir()
	if "" != szTpl {
		args = append(args, "-t", szTpl)
	} else if major > 0 && major < 3 {
		// v2 才支持 self-contained；v3 下 -sa 语义已变为 scan-all-ips，不能沿用
		args = append(args, "-sa")
	}
	if jsonOutput {
		// v2 的 -j/-json 与 v3 的 -j/-jsonl 通用
		args = append(args, "-j")
	}
	if "" != listFile {
		args = append(args, "-l", listFile)
	}
	return args
}

// RunNuclei 对给定主机列表执行 nuclei 扫描，结果写入统一输出通道
func RunNuclei(buf *bytes.Buffer) {
	if nil == buf {
		return
	}
	if !util.GetValAsBool("enableNuclei") {
		return
	}
	s001 := strings.TrimSpace(buf.String())
	if "" == s001 {
		return
	}
	a66 := strings.Split(s001, "\n")
	x55, _ := util.TestIsWeb(&a66)
	if nil == x55 || 0 == len(*x55) {
		return
	}
	bin, _, _ := NucleiInfo()
	if "" == bin {
		util.LogOnce("nuclei", "[!] nuclei 未安装或不在 PATH 中，跳过 nuclei 扫描")
		return
	}
	// 去重，避免重复目标浪费扫描时间
	targets := util.RemoveDuplication_map(append([]string{}, *x55...))

	jsonOutput := false
	if nil != util.G_Options {
		if m1, ok := util.G_Options.(map[string]interface{}); ok {
			if b, ok2 := m1["JSON"]; ok2 {
				if isJ, ok1 := b.(bool); ok1 && isJ {
					jsonOutput = true
				}
			}
		}
	}

	fT := util.GetTempFile("nuclei")
	if nil == fT {
		util.LogOnce("nuclei", "[!] 创建 nuclei 输入临时文件失败，跳过 nuclei 扫描")
		return
	}
	defer os.Remove(fT.Name())
	if _, err := fT.Write([]byte(strings.Join(targets, "\n"))); nil != err {
		util.LogOnce("nuclei-write", fmt.Sprintf("[!] 写入 nuclei 输入文件失败: %v", err))
		fT.Close()
		return
	}
	fT.Close()

	args := append([]string{bin}, BuildNucleiArgs(fT.Name(), jsonOutput)...)
	out, err := util.DoCmd(args...)
	if "" != strings.TrimSpace(out) {
		util.Writeoutput(strings.TrimRight(out, "\n"))
	}
	if nil != err {
		util.LogOnce("nuclei-exec", fmt.Sprintf("[!] nuclei 执行异常(仍可能有部分结果): %v", err))
	}
}
