package strsim

type option struct {
	ignore int  //
	ascii  bool // 设置选用ascii还是utf8方式执行算法
	cmp    func(s1, s2 string) float64
	base64 bool // 设置是否使用base64算法
}

// 调用Option接口设置option
func (o *option) fillOption(opts ...Option) {
	for _, opt := range opts {
		opt.Apply(o)
	}

	opt := Default()
	opt.Apply(o)
}

type Option interface {
	Apply(*option)
}

type OptionFunc func(*option)

func (o OptionFunc) Apply(opt *option) {
	o(opt)
}

//忽略大小写
func IgnoreCase() OptionFunc {
	return OptionFunc(func(o *option) {
		o.ignore |= ignoreCase
	})
}

//忽略空白字符
func IgnoreSpace() OptionFunc {
	return OptionFunc(func(o *option) {
		o.ignore |= ignoreSpace
	})
}

//使用ascii编码
func UseASCII() OptionFunc {
	return OptionFunc(func(o *option) {
		o.ascii = true
	})
}

// UseBase64 使用base64编码
func UseBase64() OptionFunc {
	return OptionFunc(func(o *option) {
		o.base64 = true
	})
}
