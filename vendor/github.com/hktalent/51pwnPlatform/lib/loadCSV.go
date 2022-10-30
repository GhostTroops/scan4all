package lib

import (
	_ "embed"
	"encoding/csv"
	util "github.com/hktalent/go-utils"
	"log"
	"strings"
)

//go:embed vulwh.csv
var szVulsVh string

//go:embed tmpId2vulTypes.csv
var sztmp2vultp string

// 危害说明
var Whsm = make(map[string]string)

// cat $HOME/MyWork/mybugbounty/bak/tmplate.json|jq -r '[.template.id,.vulnType]|@csv'|sort -u>/Users/51pwn/MyWork/zbServer/lib/tmpId2vulTypes.csv
//
// poc模版id 2 vul type
var Tmp2VulTp = make(map[string]string)

// 加载csv到map
func LoadCsv2Map(s09 string, m *map[string]string, n1, n2, n3 int) {
	csvReader := csv.NewReader(strings.NewReader(s09))
	records, err := csvReader.ReadAll()
	if nil == err {
		for _, x := range records {
			if n3 <= len(x) {
				(*m)[x[n1]] = x[n2]
			} else {
				log.Printf("这行数据不对: %v \n", x)
			}
		}
	} else {
		log.Printf("csvReader.ReadAll is err: %v\n", err)
	}
}

func init() {
	util.RegInitFunc(func() {
		LoadCsv2Map(szVulsVh, &Whsm, 0, 2, 3)
		LoadCsv2Map(sztmp2vultp, &Tmp2VulTp, 0, 1, 2)
	})
}

// 根据poc模版id获取危害说明
// poc "_id":26206  -->
func GetVulDesByTmpId(szId string) string {
	if id, ok := Tmp2VulTp[szId]; ok {
		if x, ok := Whsm[id]; ok {
			return x
		}
	}
	return ""
}
