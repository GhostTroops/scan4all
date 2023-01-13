package main

import "github.com/webview/webview"

const html = `<button id="increment">Tap me</button>
<div>You tapped <span id="count">0</span> time(s).</div>
<script>
  const [incrementElement, countElement] =
    document.querySelectorAll("#increment, #count");
  document.addEventListener("DOMContentLoaded", () => {
    incrementElement.addEventListener("click", () => {
      window.increment().then(result => {
        countElement.textContent = result.count;
      });
    });
  });
</script>`

type IncrementResult struct {
	Count uint `json:"count"`
}

func main() {
	//var count uint = 0
	w := webview.New(false)
	defer w.Destroy()
	w.SetTitle("51pwn hacker Platform")
	w.SetSize(480, 320, webview.HintNone)
	w.Navigate("https://127.0.0.1:8081/indexes/")
	//w.Bind("increment", func() IncrementResult {
	//	count++
	//	return IncrementResult{Count: count}
	//})
	//w.SetHtml(html)
	w.Run()
}
