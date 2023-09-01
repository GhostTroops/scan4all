package engine

import (
	"github.com/hktalent/scan4all/lib/goSqlite_gorm/lib/scan/Const"
	"github.com/hktalent/scan4all/lib/goSqlite_gorm/pkg/models"
	"github.com/hktalent/scan4all/lib/util"
	"os"
	"runtime"
	"testing"
)

func TestDispather(t *testing.T) {
	os.Args = []string{"", "-host", "http://127.0.0.1", "-v"}
	runtime.GOMAXPROCS(runtime.NumCPU())
	util.DoInit(nil)
	Dispather(&models.Target4Chan{ScanWeb: "127.0.0.1", ScanType: Const.ScanType_Masscan})
	util.Wg.Wait()
	util.CloseAll()
	//for _, tt := range tests {
	//	t.Run(tt.name, func(t *testing.T) {
	//		Dispather(tt.args.task)
	//	})
	//}
}
