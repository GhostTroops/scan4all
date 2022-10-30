package jaeles

import (
	"fmt"
	"github.com/hktalent/51pwnPlatform/lib/scan/Const"
	"github.com/hktalent/51pwnPlatform/pkg/models"
	"github.com/hktalent/ProScan4all/lib/util"
	. "github.com/hktalent/jaeles/cmd"
	"github.com/hktalent/jaeles/core"
	"github.com/hktalent/jaeles/libs"
	"github.com/hktalent/jaeles/utils"
	"github.com/thoas/go-funk"
	"math"
	"path/filepath"
)

//func init() {
//	var scanCmd = &cobra.Command{
//		Use:   "scan",
//		Short: "Scan list of URLs based on selected signatures",
//		RunE:  runScan,
//	}
//
//	scanCmd.Flags().StringP("url", "u", "", "URL of target")
//	scanCmd.Flags().StringP("urls", "U", "", "URLs file of target")
//	scanCmd.Flags().StringVarP(&options.Scan.RawRequest, "raw", "r", "", "Raw request from Burp for origin")
//	scanCmd.Flags().BoolVar(&options.Scan.EnableGenReport, "html", false, "Generate HTML report after the scan done")
//	RootCmd.AddCommand(scanCmd)
//}

func init() {
	util.RegInitFunc(func() {
		Options.ChunkLimit = math.MaxInt
		Options.RootFolder = util.SzPwd + "/"
		Options.Output = util.SzPwd + "/logs/"
		Options.SignFolder = util.SzPwd + "/config/jaeles-signatures"
		Options.ChunkRun = false     // 每个目标单独一个进程运行
		Options.NoBackGround = false // 不转到后台，显示运行
		utils.InitLog(&Options)
		core.InitConfig(&Options)
		InitDB()
		Options.SelectedSigns = core.SelectSign("**")
	})
}

// git@github.com:jaeles-project/jaeles-signatures.git
// 这玩意没有 他自定义的yarm 等于0
// urlFile 也将作为临时文件，输入
func RunScan(urls []string, urlFile string) error {
	defer util.Wg.Done()
	if 0 == len(urls) {
		return nil
	}

	// fmt.Println(os.Args)
	//SelectSign()
	// input as a file
	if urlFile != "" {
		URLs := utils.ReadingLines(urlFile)
		for _, url := range URLs {
			urls = append(urls, url)
		}
	}

	Options.ScanID = util.GetSha1(urls)
	selectedSigns := funk.UniqString(Options.SelectedSigns)
	utils.InforF("Signatures Loaded: %v", len(selectedSigns))
	signInfo := fmt.Sprintf("Signature Loaded: ")
	for _, signName := range selectedSigns {
		signInfo += fmt.Sprintf("%v ", filepath.Base(signName))
	}
	utils.InforF(signInfo)
	// only parse signature once to avoid I/O limit
	for _, signFile := range Options.SelectedSigns {
		sign, err := core.ParseSign(signFile)
		if err != nil {
			utils.ErrorF("Error parsing YAML sign: %v", signFile)
			continue
		}
		Options.ParsedSelectedSigns = append(Options.ParsedSelectedSigns, sign)
	}

	if len(urls) == 0 {
		return nil
	}

	if len(urls) > Options.ChunkLimit && !Options.ChunkRun {
		utils.WarningF("Your inputs look very big.")
		utils.WarningF("Consider using --chunk options")
	}

	utils.InforF("Input Loaded: %v", len(urls))

	/* ---- Really start do something ---- */
	// run background detector
	if !Options.NoBackGround {
		go func() {
			for {
				core.Background(Options)
			}
		}()
	}

	for _, url := range urls {
		// calculate filtering result first if enabled from cli
		baseJob := libs.Job{URL: url}
		if Options.EnableFiltering {
			core.BaseCalculateFiltering(&baseJob, Options)
		}
		for _, sign := range Options.ParsedSelectedSigns {
			// filter signature by level
			if sign.Level > Options.Level {
				continue
			}
			sign.Checksums = baseJob.Checksums
			// Submit tasks one by one.
			job := libs.Job{URL: url, Sign: sign}
			//_ = p.Invoke(job)
			util.SendEvent(&models.EventData{EventType: Const.ScanType_Jaeles, EventData: []interface{}{job}}, Const.ScanType_Jaeles)
		}
	}

	if Options.Scan.EnableGenReport && utils.FolderExists(Options.Output) {
		DoGenReport(Options)
	}
	return nil
}

// 注册 当前类型
func init() {
	util.RegInitFunc(func() {
		util.EngineFuncFactory(Const.ScanType_Jaeles, func(evt *models.EventData, args ...interface{}) {
			CreateRunner(evt.EventData[0])
		})
	})
}
