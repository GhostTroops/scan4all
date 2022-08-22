package js

import (
	"fmt"
	"github.com/chromedp/cdproto/cdp"
)

const TabInitJS = `
(function addTabInitScript () {

	// Pass the Webdriver Test.
	Object.defineProperty(navigator, 'webdriver', {
        get: () => false,
    });

	// Pass the Plugins Length Test.
	// Overwrite the plugins property to use a custom getter.
	Object.defineProperty(navigator, 'plugins', {
        // This just needs to have length > 0 for the current test,
        // but we could mock the plugins too if necessary.
        get: () => [1, 2, 3, 4, 5],
    });
	
	// Pass the Chrome Test.
	// We can mock this in as much depth as we need for the test.
	window.chrome = {
		runtime: {},
	};

	// Pass the Permissions Test.
  	const originalQuery = window.navigator.permissions.query;
	window.navigator.permissions.query = (parameters) => (
    	parameters.name === 'notifications' ?
			Promise.resolve({ state: Notification.permission }) :
			originalQuery(parameters)
	);

	//Pass the Permissions Test. navigator.userAgent
	Object.defineProperty(navigator, 'userAgent', {
        get: () => "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.0 Safari/537.36",
    });

	// 修改浏览器对象的属性
	Object.defineProperty(navigator, 'platform', {
		get: function () { return 'win32'; }
	});
	
	Object.defineProperty(navigator, 'language', {
		get: function () { return 'zh-CN'; }
	});
	
	Object.defineProperty(navigator, 'languages', {
		get: function () { return ["zh-CN", "zh"]; }
	});
	
	// history api hook
	window.history.pushState = function(a, b, c) { 
		window.addLink(c, "HistoryAPI");
	}
	window.history.replaceState = function(a, b, c) { 
		window.addLink(c, "HistoryAPI");
	}
	Object.defineProperty(window.history,"pushState",{"writable": false, "configurable": false});
	Object.defineProperty(window.history,"replaceState",{"writable": false, "configurable": false});
	// 监听hash改变
	window.addEventListener("hashchange", function() {
		window.addLink(document.location.href, "HashChange");
	});
	
	var oldWebSocket = window.WebSocket;
	window.WebSocket = function(url, arg) {
		window.addLink(url, "WebSocket");
		return new oldWebSocket(url, arg);
	}
	
	var oldEventSource = window.EventSource;
	window.EventSource = function(url) {
		window.addLink(url, "EventSource");
		return new oldEventSource(url);
	}
	
	var oldFetch = window.fetch;
	window.fetch = function(url) {
		window.addLink(url, "Fetch");
		return oldFetch(url);
	}
	
	// 锁定表单重置
	HTMLFormElement.prototype.reset = function() {console.log("cancel reset form")};
	Object.defineProperty(HTMLFormElement.prototype,"reset",{"writable": false, "configurable": false});
	
	// hook dom2 级事件监听
	window.add_even_listener_count_sec_auto = {};
	// record event func , hook addEventListener
	let old_event_handle = Element.prototype.addEventListener;
	Element.prototype.addEventListener = function(event_name, event_func, useCapture) {
		let name = "<" + this.tagName + "> " + this.id + this.name + this.getAttribute("class") + "|" + event_name;
		// console.log(name)
		// 对每个事件设定最大的添加次数，防止无限触发，最大次数为5
		if (!window.add_even_listener_count_sec_auto.hasOwnProperty(name)) {
			window.add_even_listener_count_sec_auto[name] = 1;
		} else if (window.add_even_listener_count_sec_auto[name] == 5) {
			return ;
		} else {
			 window.add_even_listener_count_sec_auto[name] += 1;
		}
		if (this.hasAttribute("sec_auto_dom2_event_flag")) {
			let sec_auto_dom2_event_flag = this.getAttribute("sec_auto_dom2_event_flag");
			this.setAttribute("sec_auto_dom2_event_flag", sec_auto_dom2_event_flag + "|" + event_name);
		} else {
			this.setAttribute("sec_auto_dom2_event_flag", event_name);
		}
		old_event_handle.apply(this, arguments);
	};
	
	function dom0_listener_hook(that, event_name) {
		let name = "<" + that.tagName + "> " + that.id + that.name + that.getAttribute("class") + "|" + event_name;
		// console.log(name);
		// 对每个事件设定最大的添加次数，防止无限触发，最大次数为5
		if (!window.add_even_listener_count_sec_auto.hasOwnProperty(name)) {
			window.add_even_listener_count_sec_auto[name] = 1;
		} else if (window.add_even_listener_count_sec_auto[name] == 5) {
			return ;
		} else {
			 window.add_even_listener_count_sec_auto[name] += 1;
		}
		if (that.hasAttribute("sec_auto_dom2_event_flag")) {
			let sec_auto_dom2_event_flag = that.getAttribute("sec_auto_dom2_event_flag");
			that.setAttribute("sec_auto_dom2_event_flag", sec_auto_dom2_event_flag + "|" + event_name);
		} else {
			that.setAttribute("sec_auto_dom2_event_flag", event_name);
		}
	}
	
	// hook dom0 级事件监听
	Object.defineProperties(HTMLElement.prototype, {
		onclick: {set: function(newValue){onclick = newValue;dom0_listener_hook(this, "click");}},
		onchange: {set: function(newValue){onchange = newValue;dom0_listener_hook(this, "change");}},
		onblur: {set: function(newValue){onblur = newValue;dom0_listener_hook(this, "blur");}},
		ondblclick: {set: function(newValue){ondblclick = newValue;dom0_listener_hook(this, "dbclick");}},
		onfocus: {set: function(newValue){onfocus = newValue;dom0_listener_hook(this, "focus");}},
		onkeydown: {set: function(newValue){onkeydown = newValue;dom0_listener_hook(this, "keydown");}},
		onkeypress: {set: function(newValue){onkeypress = newValue;dom0_listener_hook(this, "keypress");}},
		onkeyup: {set: function(newValue){onkeyup = newValue;dom0_listener_hook(this, "keyup");}},
		onload: {set: function(newValue){onload = newValue;dom0_listener_hook(this, "load");}},
		onmousedown: {set: function(newValue){onmousedown = newValue;dom0_listener_hook(this, "mousedown");}},
		onmousemove: {set: function(newValue){onmousemove = newValue;dom0_listener_hook(this, "mousemove");}},
		onmouseout: {set: function(newValue){onmouseout = newValue;dom0_listener_hook(this, "mouseout");}},
		onmouseover: {set: function(newValue){onmouseover = newValue;dom0_listener_hook(this, "mouseover");}},
		onmouseup: {set: function(newValue){onmouseup = newValue;dom0_listener_hook(this, "mouseup");}},
		onreset: {set: function(newValue){onreset = newValue;dom0_listener_hook(this, "reset");}},
		onresize: {set: function(newValue){onresize = newValue;dom0_listener_hook(this, "resize");}},
		onselect: {set: function(newValue){onselect = newValue;dom0_listener_hook(this, "select");}},
		onsubmit: {set: function(newValue){onsubmit = newValue;dom0_listener_hook(this, "submit");}},
		onunload: {set: function(newValue){onunload = newValue;dom0_listener_hook(this, "unload");}},
		onabort: {set: function(newValue){onabort = newValue;dom0_listener_hook(this, "abort");}},
		onerror: {set: function(newValue){onerror = newValue;dom0_listener_hook(this, "error");}},
	})
	
	// hook window.open 
	window.open = function (url) {
		console.log("trying to open window.");
		window.addLink(url, "OpenWindow");
	}
	Object.defineProperty(window,"open",{"writable": false, "configurable": false});
	
	// hook window close
	window.close = function() {console.log("trying to close page.");};
	Object.defineProperty(window,"close",{"writable": false, "configurable": false});
	
	// hook setTimeout
	//window.__originalSetTimeout = window.setTimeout;
	//window.setTimeout = function() {
	//    arguments[1] = 0;
	//    return window.__originalSetTimeout.apply(this, arguments);
	//};
	//Object.defineProperty(window,"setTimeout",{"writable": false, "configurable": false});
	
	// hook setInterval 时间设置为60秒 目的是减轻chrome的压力
	window.__originalSetInterval = window.setInterval;
	window.setInterval = function() {
		arguments[1] = 60000;
		return window.__originalSetInterval.apply(this, arguments);
	};
	Object.defineProperty(window,"setInterval",{"writable": false, "configurable": false});
	
	// 劫持原生ajax，并对每个请求设置最大请求次数
	window.ajax_req_count_sec_auto = {};
	XMLHttpRequest.prototype.__originalOpen = XMLHttpRequest.prototype.open;
	XMLHttpRequest.prototype.open = function(method, url, async, user, password) {
		// hook code
		this.url = url;
		this.method = method;
		let name = method + url;
		if (!window.ajax_req_count_sec_auto.hasOwnProperty(name)) {
			window.ajax_req_count_sec_auto[name] = 1
		} else {
			window.ajax_req_count_sec_auto[name] += 1
		}
		
		if (window.ajax_req_count_sec_auto[name] <= 10) {
			return this.__originalOpen(method, url, true, user, password);
		}
	}
	Object.defineProperty(XMLHttpRequest.prototype,"open",{"writable": false, "configurable": false});
	
	XMLHttpRequest.prototype.__originalSend = XMLHttpRequest.prototype.send;
	XMLHttpRequest.prototype.send = function(data) {
		// hook code
		let name = this.method + this.url;
		if (window.ajax_req_count_sec_auto[name] <= 10) {
			return this.__originalSend(data);
		}
	}
	Object.defineProperty(XMLHttpRequest.prototype,"send",{"writable": false, "configurable": false});

	XMLHttpRequest.prototype.__originalAbort = XMLHttpRequest.prototype.abort;
	XMLHttpRequest.prototype.abort = function() {
		// hook code
	}
	Object.defineProperty(XMLHttpRequest.prototype,"abort",{"writable": false, "configurable": false});
	
	// 打乱数组的方法
	window.randArr = function (arr) {
		for (var i = 0; i < arr.length; i++) {
			var iRand = parseInt(arr.length * Math.random());
			var temp = arr[i];
			arr[i] = arr[iRand];
			arr[iRand] = temp;
		}
		return arr;
	}
	
	window.sleep = function(time) {
		return new Promise((resolve) => setTimeout(resolve, time));
	}
	
	Array.prototype.indexOf = function(val) {
		for (var i = 0; i < this.length; i++) {
			if (this[i] == val) return i;
		}
		return -1;
	};
	
	Array.prototype.remove = function(val) {
		var index = this.indexOf(val);
		if (index > -1) {
			this.splice(index, 1);
		}
	};

	const binding = window["addLink"];
	window["addLink"] = async(...args) => {
		const me = window["addLink"];
		let callbacks = me['callbacks'];
		if (!callbacks) {
		  callbacks = new Map();
		  me['callbacks'] = callbacks;
		}
		const seq = (me['lastSeq'] || 0) + 1;
		me['lastSeq'] = seq;
		const promise = new Promise(fulfill => callbacks.set(seq, fulfill));
		binding(JSON.stringify({name: "addLink", seq, args}));
		return promise;
	};

	const bindingTest = window["Test"];
	window["Test"] = async(...args) => {
		const me = window["Test"];
		let callbacks = me['callbacks'];
		if (!callbacks) {
		  callbacks = new Map();
		  me['callbacks'] = callbacks;
		}
		const seq = (me['lastSeq'] || 0) + 1;
		me['lastSeq'] = seq;
		const promise = new Promise(fulfill => callbacks.set(seq, fulfill));
		binding(JSON.stringify({name: "Test", seq, args}));
		return promise;
	};
})();
`

const DeliverResultJS = `
(function deliverResult(name, seq, result) {
	window[name]['callbacks'].get(seq)(result);
	window[name]['callbacks'].delete(seq);
})("%s", %v, "%s")
`

const ObserverJS = `
(function init_observer_sec_auto_b() {
	window.dom_listener_func_sec_auto = function (e) {
		let node = e.target;
		let nodeListSrc = node.querySelectorAll("[src]");
		for (let each of nodeListSrc) {
			if (each.src) {
				window.addLink(each.src, "DOM");
				let attrValue = each.getAttribute("src");
				if (attrValue.toLocaleLowerCase().startsWith("javascript:")) {
					try {
						eval(attrValue.substring(11));
					}
					catch {}
				}
			}
		}
		
		let nodeListHref = node.querySelectorAll("[href]");
		nodeListHref = window.randArr(nodeListHref);
		for (let each of nodeListHref) {
			if (each.href) {
				window.addLink(each.href, "DOM");
				let attrValue = each.getAttribute("href");
				if (attrValue.toLocaleLowerCase().startsWith("javascript:")) {
					try {
						eval(attrValue.substring(11));
					}
					catch {}
				}
			}
		}
	};
	document.addEventListener('DOMNodeInserted', window.dom_listener_func_sec_auto, true);
	document.addEventListener('DOMSubtreeModified', window.dom_listener_func_sec_auto, true);
	document.addEventListener('DOMNodeInsertedIntoDocument', window.dom_listener_func_sec_auto, true);
	document.addEventListener('DOMAttrModified', window.dom_listener_func_sec_auto, true);
})()
`

const RemoveDOMListenerJS = `
(function remove_dom_listener() {
	document.removeEventListener('DOMNodeInserted', window.dom_listener_func_sec_auto, true);
	document.removeEventListener('DOMSubtreeModified', window.dom_listener_func_sec_auto, true);
	document.removeEventListener('DOMNodeInsertedIntoDocument', window.dom_listener_func_sec_auto, true);
	document.removeEventListener('DOMAttrModified', window.dom_listener_func_sec_auto, true);
})()
`

const NewFrameTemplate = `
(function sec_auto_new_iframe () {
	let frame = document.createElement("iframe");
	frame.setAttribute("name", "%s");
	frame.setAttribute("id", "%s");
	frame.setAttribute("style", "display: none");
	document.body.appendChild(frame);
})()
`

const TriggerInlineEventJS = `
(async function trigger_all_inline_event(){
	let eventNames = ["onabort", "onblur", "onchange", "onclick", "ondblclick", "onerror", "onfocus", "onkeydown", "onkeypress", "onkeyup", "onload", "onmousedown", "onmousemove", "onmouseout", "onmouseover", "onmouseup", "onreset", "onresize", "onselect", "onsubmit", "onunload"];
	for (let eventName of eventNames) {
		let event = eventName.replace("on", "");
		let nodeList = document.querySelectorAll("[" + eventName + "]");
		if (nodeList.length > 100) {
			nodeList = nodeList.slice(0, 100);
		}
		nodeList = window.randArr(nodeList);
		for (let node of nodeList) {
			await window.sleep(%f);
			let evt = document.createEvent('CustomEvent');
			evt.initCustomEvent(event, false, true, null);
			try {
				node.dispatchEvent(evt);
			}
			catch {}
		}
	}
})()
`

const TriggerDom2EventJS = `
(async function trigger_all_dom2_custom_event() {
	function transmit_child(node, event, loop) {
		let _loop = loop + 1
		if (_loop > 4) {
			return;
		}
		if (node.nodeType === 1) {
			if (node.hasChildNodes) {
				let index = parseInt(Math.random()*node.children.length,10);
				try {
					node.children[index].dispatchEvent(event);
				} catch(e) {}
				let max = node.children.length>5?5:node.children.length;
				for (let count=0;count<max;count++) {
					let index = parseInt(Math.random()*node.children.length,10);
					transmit_child(node.children[index], event, _loop);
				}
			}
		}
	}
	let nodes = document.querySelectorAll("[sec_auto_dom2_event_flag]");
	if (nodes.length > 200) {
		nodes = nodes.slice(0, 200);
	}
	nodes = window.randArr(nodes);
	for (let node of nodes) {
		let loop = 0;
		await window.sleep(%f);
		let event_name_list = node.getAttribute("sec_auto_dom2_event_flag").split("|");
		let event_name_set = new Set(event_name_list);
		event_name_list = [...event_name_set];
		for (let event_name of event_name_list) {
			let evt = document.createEvent('CustomEvent');
			evt.initCustomEvent(event_name, true, true, null);
			
			if (event_name == "click" || event_name == "focus" || event_name == "mouseover" || event_name == "select") {
				transmit_child(node, evt, loop);
			}
			if ( (node.className && node.className.includes("close")) || (node.id && node.id.includes("close"))) {
				continue;
			}
			
			try {
				node.dispatchEvent(evt);
			} catch(e) {}
		}
	}
})()
`

const TriggerJavascriptProtocol = `
(async function click_all_a_tag_javascript(){
	let nodeListHref = document.querySelectorAll("[href]");
	nodeListHref = window.randArr(nodeListHref);
	for (let node of nodeListHref) {
		let attrValue = node.getAttribute("href");
		if (attrValue.toLocaleLowerCase().startsWith("javascript:")) {
			await window.sleep(%f);
			try {
				eval(attrValue.substring(11));
			}
			catch {}
		}
	}
	let nodeListSrc = document.querySelectorAll("[src]");
	nodeListSrc = window.randArr(nodeListSrc);
	for (let node of nodeListSrc) {
		let attrValue = node.getAttribute("src");
		if (attrValue.toLocaleLowerCase().startsWith("javascript:")) {
			await window.sleep(%f);
			try {
				eval(attrValue.substring(11));
			}
			catch {}
		}
	}
})()
`

const FormNodeClickJS = `
(function(a) {
	try {
		a.click();
		return true;
	} catch(e) {
		return false;
	}
})(%s)
`

func Snippet(js string, f func(n *cdp.Node) string, sel string, n *cdp.Node, v ...interface{}) string {
	//return fmt.Sprintf(js, append([]interface{}{sel}, v...)...)
	return fmt.Sprintf(js, append([]interface{}{f(n)}, v...)...)
}

func CashX(flatten bool) func(*cdp.Node) string {
	return func(n *cdp.Node) string {
		if flatten {
			return fmt.Sprintf(`$x(%q)[0]`, n.FullXPath())
		}
		return fmt.Sprintf(`$x(%q)`, n.FullXPath())
	}
}
