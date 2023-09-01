package permissionutil

var (
	IsRoot       bool
	HasCapNetRaw bool
)

func init() {
	IsRoot, _ = checkCurrentUserRoot()
	HasCapNetRaw, _ = checkCurrentUserCapNetRaw()
}
