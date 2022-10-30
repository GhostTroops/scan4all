package cmd

import (
	"bufio"
	"fmt"
	"github.com/hktalent/jaeles/core"
	"github.com/hktalent/jaeles/libs"
	"github.com/hktalent/jaeles/utils"
	"github.com/panjf2000/ants"
	"github.com/spf13/cobra"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
)

func init() {
	var scanCmd = &cobra.Command{
		Use:   "scan",
		Short: "Scan list of URLs based on selected signatures",
		Long:  libs.Banner(),
		RunE:  runScan,
	}

	scanCmd.Flags().StringP("url", "u", "", "URL of target")
	scanCmd.Flags().StringP("urls", "U", "", "URLs file of target")
	scanCmd.Flags().StringVarP(&Options.Scan.RawRequest, "raw", "r", "", "Raw request from Burp for origin")
	scanCmd.Flags().BoolVar(&Options.Scan.EnableGenReport, "html", false, "Generate HTML report after the scan done")
	scanCmd.SetHelpFunc(ScanHelp)
	RootCmd.AddCommand(scanCmd)
}

func runScan(cmd *cobra.Command, _ []string) error {
	// fmt.Println(os.Args)
	SelectSign()
	var urls []string
	// parse URL input here
	urlFile, _ := cmd.Flags().GetString("urls")
	urlInput, _ := cmd.Flags().GetString("url")
	if urlInput != "" {
		urls = append(urls, urlInput)
	}
	// input as a file
	if urlFile != "" {
		URLs := utils.ReadingLines(urlFile)
		for _, url := range URLs {
			urls = append(urls, url)
		}
	}

	// input as stdin
	if len(urls) == 0 {
		stat, _ := os.Stdin.Stat()
		// detect if anything came from std
		if (stat.Mode() & os.ModeCharDevice) == 0 {
			sc := bufio.NewScanner(os.Stdin)
			for sc.Scan() {
				url := strings.TrimSpace(sc.Text())
				if err := sc.Err(); err == nil && url != "" {
					urls = append(urls, url)
				}
			}
			// store stdin as a temp file
			if len(urls) > Options.ChunkLimit && Options.ChunkRun {
				urlFile = path.Join(Options.ChunkDir, fmt.Sprintf("raw-%v", core.RandomString(8)))
				utils.InforF("Write stdin data to: %v", urlFile)
				utils.WriteToFile(urlFile, strings.Join(urls, "\n"))
			}
		}
	}

	if len(urls) == 0 {
		fmt.Fprintf(os.Stderr, "[Error] No input loaded\n")
		fmt.Fprintf(os.Stderr, "Use 'jaeles -h' for more information about a command.\n")
		os.Exit(1)
	}

	if len(urls) > Options.ChunkLimit && !Options.ChunkRun {
		utils.WarningF("Your inputs look very big.")
		utils.WarningF("Consider using --chunk Options")
	}
	if len(urls) > Options.ChunkLimit && Options.ChunkRun {
		utils.InforF("Running Jaeles in Chunk mode")
		rawCommand := strings.Join(os.Args, " ")

		if strings.Contains(rawCommand, "-U ") {
			rawCommand = strings.ReplaceAll(rawCommand, fmt.Sprintf("-U %v", urlFile), "-U {}")
		} else {
			rawCommand += " -U {}"
		}
		urlFiles := genChunkFiles(urlFile, Options)
		runChunk(rawCommand, urlFiles, Options.ChunkThreads)
		for _, chunkFile := range urlFiles {
			os.RemoveAll(chunkFile)
		}
		os.Exit(0)
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

	var wg sync.WaitGroup
	p, _ := ants.NewPoolWithFunc(Options.Concurrency, func(i interface{}) {
		CreateRunner(i)
		wg.Done()
	}, ants.WithPreAlloc(true))
	defer p.Release()

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

			wg.Add(1)
			// Submit tasks one by one.
			job := libs.Job{URL: url, Sign: sign}
			_ = p.Invoke(job)
		}
	}

	wg.Wait()
	CleanOutput()

	if Options.Scan.EnableGenReport && utils.FolderExists(Options.Output) {
		DoGenReport(Options)
	}
	return nil
}

func CreateRunner(j interface{}) {
	var jobs []libs.Job
	rawJob := j.(libs.Job)

	if rawJob.Sign.Type == "dns" {
		CreateDnsRunner(rawJob)
		return
	}

	// enable local analyze
	if Options.LocalAnalyze {
		core.LocalFileToResponse(&rawJob)
	}

	// auto prepend http and https prefix if not present
	if !Options.LocalAnalyze && !strings.HasPrefix(rawJob.URL, "http://") && !strings.HasPrefix(rawJob.URL, "https://") {
		withPrefixJob := rawJob
		withPrefixJob.URL = "http://" + rawJob.URL
		jobs = append(jobs, withPrefixJob)

		withPrefixJob = rawJob
		withPrefixJob.URL = "https://" + rawJob.URL
		jobs = append(jobs, withPrefixJob)
	} else {
		jobs = append(jobs, rawJob)
	}

	if (rawJob.Sign.Replicate.Ports != "" || rawJob.Sign.Replicate.Prefixes != "") && !Options.Mics.DisableReplicate {
		if Options.Mics.BaseRoot {
			rawJob.Sign.BasePath = true
		}
		moreJobs, err := core.ReplicationJob(rawJob.URL, rawJob.Sign)
		if err == nil {
			jobs = append(jobs, moreJobs...)
		}
	}

	for _, job := range jobs {
		// custom calculate filtering if enabled inside signature
		if job.Sign.Filter || len(job.Sign.FilteringPaths) > 0 {
			core.CalculateFiltering(&job, Options)
		}
		utils.DebugF("Raw Checksum: %v", job.Sign.Checksums)

		if job.Sign.Type == "routine" {
			routine, err := core.InitRoutine(job.URL, job.Sign, Options)
			if err != nil {
				utils.ErrorF("Error create new routine: %v", err)
			}
			routine.Start()
			continue
		}
		runner, err := core.InitRunner(job.URL, job.Sign, Options)
		if err != nil {
			utils.ErrorF("Error create new runner: %v", err)
		}
		runner.Sending()
	}
}

// CreateDnsRunner create runner for dns
func CreateDnsRunner(job libs.Job) {
	runner, err := core.InitDNSRunner(job.URL, job.Sign, Options)
	if err != nil {
		utils.ErrorF("Error create new dns runner: %v", err)
	}
	runner.Resolving()
}

/////////////////////// Chunk Options (very experimental)

func genChunkFiles(urlFile string, options libs.Options) []string {
	utils.DebugF("Store tmp chunk data at: %v", options.ChunkDir)
	var divided [][]string
	var chunkFiles []string
	divided = utils.ChunkFileBySize(urlFile, options.ChunkSize)
	for index, chunk := range divided {
		outName := path.Join(options.ChunkDir, fmt.Sprintf("%v-%v", core.RandomString(6), index))
		utils.WriteToFile(outName, strings.Join(chunk, "\n"))
		chunkFiles = append(chunkFiles, outName)
	}
	return chunkFiles
}

func runChunk(command string, urlFiles []string, threads int) {
	utils.DebugF("Run chunk command with template: %v", command)

	var commands []string
	for index, urlFile := range urlFiles {
		cmd := command
		cmd = strings.Replace(cmd, "{}", urlFile, -1)
		cmd = strings.Replace(cmd, "{#}", fmt.Sprintf("%d", index), -1)
		commands = append(commands, cmd)
	}

	var wg sync.WaitGroup
	p, _ := ants.NewPoolWithFunc(threads, func(i interface{}) {
		cmd := i.(string)
		ExecutionWithStd(cmd)
		wg.Done()
	}, ants.WithPreAlloc(true))
	defer p.Release()
	for _, cmd := range commands {
		wg.Add(1)
		_ = p.Invoke(cmd)
	}
	wg.Wait()
}

// ExecutionWithStd Run a command
func ExecutionWithStd(cmd string) (string, error) {
	command := []string{
		"bash",
		"-c",
		cmd,
	}
	var output string
	realCmd := exec.Command(command[0], command[1:]...)
	// output command output to std too
	cmdReader, _ := realCmd.StdoutPipe()
	scanner := bufio.NewScanner(cmdReader)
	var out string
	go func() {
		for scanner.Scan() {
			out += scanner.Text()
			//fmt.Fprintf(os.Stderr, scanner.Text()+"\n")
			fmt.Println(scanner.Text())
		}
	}()
	if err := realCmd.Start(); err != nil {
		return "", err
	}
	if err := realCmd.Wait(); err != nil {
		return "", err
	}
	return output, nil
}
