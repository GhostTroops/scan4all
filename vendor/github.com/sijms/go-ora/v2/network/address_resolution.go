package network

const (
	DefaultAddress string = "(Description=(Address=(Protocol=tcp)(IP=loopback)(port=1521))(CONNECT_DATA=(SID="
)

type AddressResolution struct {
	InstanceName string
	TNSAddress   string
}

//func ResolveEZConnect(tnsAlias string, instanceName string) (*ConnectionOption, error) {
//	op := ConnectionOption{
//		Protocol: "tcp",
//		SessionDataUnitSize: 0xFFFF,
//		TransportDataUnitSize: 0xFFFF,
//	}
//	startIndex := 0
//	endIndex := 0
//	if strings.HasPrefix(tnsAlias, "//") {
//		startIndex = 2
//	}
//	if tnsAlias[startIndex] == '[' {
//		endIndex = strings.Index(tnsAlias[startIndex:], "]")
//		if endIndex == -1 {
//			return nil, errors.New("outData source contain [ without closing ]")
//		}
//		startIndex ++
//		if endIndex <= startIndex {
//			return nil, errors.New("outData source contain [ without closing ]")
//		}
//		op.Host = tnsAlias[startIndex: endIndex]
//		startIndex = endIndex + 1
//	} else {
//		endIndex = strings.IndexAny(tnsAlias[startIndex:], ":/")
//		if endIndex == -1 {
//			endIndex = len(tnsAlias)
//		}
//		op.Host = tnsAlias[startIndex: endIndex]
//		startIndex = endIndex
//	}
//	if endIndex < len(tnsAlias) {
//		if tnsAlias[endIndex] == ':' {
//			startIndex ++
//			endIndex = strings.IndexAny(tnsAlias[startIndex:], ":/")
//			if endIndex == -1 {
//				endIndex = len(tnsAlias)
//			}
//			var err error
//			op.Port, err = strconv.Atoi(tnsAlias[startIndex: endIndex])
//			if err != nil {
//				return nil, errors.New("port must be a number")
//			}
//			startIndex = endIndex
//		}
//	}
//}
