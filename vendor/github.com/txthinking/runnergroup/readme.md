## RunnerGroup

[![GoDoc](https://img.shields.io/badge/Go-Doc-blue.svg)](https://godoc.org/github.com/txthinking/runnergroup)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://github.com/txthinking/runnergroup/blob/master/LICENSE)

[🗣 News](https://t.me/txthinking_news)
[💬 Chat](https://join.txthinking.com)
[🩸 Youtube](https://www.youtube.com/txthinking) 
[❤️ Sponsor](https://github.com/sponsors/txthinking)

RunnerGroup is like [sync.WaitGroup](https://pkg.go.dev/sync?tab=doc#WaitGroup), the diffrence is if one task stops, all will be stopped.

❤️ A project by [txthinking.com](https://www.txthinking.com)

### Install

    $ go get github.com/txthinking/runnergroup

### Example

```
import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/txthinking/runnergroup"
)

func Example() {
	g := runnergroup.New()

	s := &http.Server{
		Addr: ":9991",
	}
	g.Add(&runnergroup.Runner{
		Start: func() error {
			return s.ListenAndServe()
		},
		Stop: func() error {
			return s.Shutdown(context.Background())
		},
	})

	s1 := &http.Server{
		Addr: ":9992",
	}
	g.Add(&runnergroup.Runner{
		Start: func() error {
			return s1.ListenAndServe()
		},
		Stop: func() error {
			return s1.Shutdown(context.Background())
		},
	})

	go func() {
		time.Sleep(5 * time.Second)
		log.Println(g.Done())
	}()
	log.Println(g.Wait())
	// Output:
}

```

## License

Licensed under The MIT License
