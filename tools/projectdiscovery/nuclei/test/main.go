package main

/*
#cgo LDFLAGS: -ldl

#include <stdlib.h>
#include <dlfcn.h>

typedef (*main) ();

*/
import (
	"C"
)

// https://github.com/webview/webview/blob/master/webview_test.go
// https://rosettacode.org/wiki/Call_a_function_in_a_shared_library#Go
// https://www.mathworks.com/help/rtw/ug/export-generated-shared-libraries.html
func main() {
	//plugin.Open()
	//// 加载so文件
	//libpath := C.CString("../nuclei.so")
	//libc, err := C.dlopen(libpath, C.RTLD_NOW|C.RTLD_GLOBAL)
	//if err != nil {
	//	panic("error loading shared library")
	//}
	//defer C.free(unsafe.Pointer(libpath))
	//defer C.dlclose(libc)
	//
	//// 加载so中的方法
	//szMain := C.CString("main")
	//defer C.free(unsafe.Pointer(szMain))
	//cFunc, err := C.dlsym(libc, szMain)
	//if err != nil {
	//	panic("error finding symbol")
	//}
	//os.Args = []string{"", "-version"}
	//C.main()
	//// 调用so中的方法
	//C.callFromC(cFunc)
}
