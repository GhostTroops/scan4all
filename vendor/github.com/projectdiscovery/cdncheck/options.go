package cdncheck

type Options struct {
	Cache       bool
	IPInfoToken string
}

func (options *Options) HasAuthInfo() bool {
	return options.IPInfoToken != ""
}
