package processbar

import "github.com/boy-hack/ksubdomain/core/gologger"

type ScreenProcess struct {
}

func (s *ScreenProcess) WriteData(data *ProcessData) {
	gologger.Printf("\rSuccess:%d Send:%d Queue:%d Accept:%d Fail:%d Elapsed:%ds", data.SuccessIndex, data.SendIndex, data.QueueLength, data.RecvIndex, data.FaildIndex, data.Elapsed)
}

func (s *ScreenProcess) Close() {

}
