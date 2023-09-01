//go:build (arm || arm64) && windows

package disk

func init() {
	OpenPogrebDB = func(_ string) (DB, error) {
		return nil, ErrNotSupported
	}
}
