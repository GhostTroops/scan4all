package cmd

import (
	"fmt"
	"github.com/panjf2000/ants"
	"os"
	"path"
	"path/filepath"
	"sync"

	"github.com/hktalent/jaeles/core"
	"github.com/hktalent/jaeles/database"
	"github.com/hktalent/jaeles/libs"
	"github.com/hktalent/jaeles/server"
	"github.com/hktalent/jaeles/utils"

	"github.com/spf13/cobra"
)

func init() {
	var serverCmd = &cobra.Command{
		Use:   "server",
		Short: "Start API server",
		Long:  libs.Banner(), RunE: runServer,
	}
	serverCmd.Flags().String("host", "127.0.0.1", "IP address to bind the server")
	serverCmd.Flags().String("port", "5000", "Port")
	serverCmd.Flags().BoolP("no-auth", "A", false, "Turn off authenticated on API server")
	serverCmd.SetHelpFunc(ServerHelp)
	RootCmd.AddCommand(serverCmd)
}

func runServer(cmd *cobra.Command, _ []string) error {
	if Options.NoDB {
		fmt.Fprintf(os.Stderr, "Can't run Jaeles Server without DB\n")
		os.Exit(-1)
	}
	SelectSign()
	// prepare DB stuff
	if Options.Server.Username != "" {
		database.CreateUser(Options.Server.Username, Options.Server.Password)
	}
	// reload signature
	SignFolder, _ := filepath.Abs(path.Join(Options.RootFolder, "base-signatures"))
	allSigns := utils.GetFileNames(SignFolder, ".yaml")
	if allSigns != nil {
		for _, signFile := range allSigns {
			database.ImportSign(signFile)
		}
	}
	database.InitConfigSign()

	var wg sync.WaitGroup
	p, _ := ants.NewPoolWithFunc(Options.Concurrency, func(i interface{}) {
		CreateRunner(i)
		wg.Done()
	}, ants.WithPreAlloc(true))
	defer p.Release()

	result := make(chan libs.Record)
	go func() {
		for {
			record := <-result
			utils.InforF("[Receive] %v %v \n", record.OriginReq.Method, record.OriginReq.URL)
			for _, signFile := range Options.SelectedSigns {
				sign, err := core.ParseSign(signFile)
				if err != nil {
					utils.ErrorF("Error loading sign: %v\n", signFile)
					continue
				}
				// filter signature by level
				if sign.Level > Options.Level {
					continue
				}

				// parse sign as list or single
				var url string
				if sign.Type != "fuzz" {
					url = record.OriginReq.URL
				} else {
					fuzzSign := sign
					fuzzSign.Requests = []libs.Request{}
					for _, req := range sign.Requests {
						core.ParseRequestFromServer(&record, req, sign)
						// override the original if these field defined in signature
						if req.Method == "" {
							req.Method = record.OriginReq.Method
						}
						if req.URL == "" {
							req.URL = record.OriginReq.URL
						}
						if len(req.Headers) == 0 {
							req.Headers = record.OriginReq.Headers
						}
						if req.Body == "" {
							req.Body = record.OriginReq.Body
						}
						fuzzSign.Requests = append(fuzzSign.Requests, req)
					}
					url = record.OriginReq.URL
					sign = fuzzSign
				}

				// single routine
				wg.Add(1)
				job := libs.Job{URL: url, Sign: sign}
				_ = p.Invoke(job)
			}
		}
	}()

	host, _ := cmd.Flags().GetString("host")
	port, _ := cmd.Flags().GetString("port")
	Options.Server.NoAuth, _ = cmd.Flags().GetBool("no-auth")
	bind := fmt.Sprintf("%v:%v", host, port)
	Options.Server.Bind = bind
	utils.GoodF("Start API server at %v", fmt.Sprintf("http://%v/", bind))
	server.InitRouter(Options, result)
	wg.Wait()
	if utils.DirLength(Options.Output) == 0 {
		os.RemoveAll(Options.Output)
	}
	return nil
}
