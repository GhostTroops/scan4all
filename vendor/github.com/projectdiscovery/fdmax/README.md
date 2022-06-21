# fdmax
Small Helper library that increases automatically the maximum number of file descriptors for the current go program.
It can be simply imported as follows:

```
package main

import (
	"fmt"

	_ "github.com/projectdiscovery/fdmax/autofdmax"
)

func main() {
	fmt.Println("test")
}
```
