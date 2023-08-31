# urlutil
The package contains various helpers to interact with URLs

## difference b/w `net/url.URL` and `utils/url/URL`

- `url.URL` caters to variety of urls and for that reason its parsing is not that accurate under various conditions
- `utils/url/URL` is a wrapper around `url.URL` that handles below edgecases and is able to parse complex (i.e non-RFC compilant urls but required in infosec) url edgecases.
- `url.URL` allows `u.Path` without `/` prefix but it is not allowed in `utils/url/URL` and is autocorrected if `/` prefix is missing

- Parsing URLs without `scheme`

```
// if below urls are parsed with url.Parse(). url parts(scheme,host,path etc) are not properly classified
scanme.sh
scanme.sh:443/port
scame.sh/with/path
```

- Encoding of parameters(url.Values)
  - `url.URL` encodes all reserved characters(as per RFC(s)) in parameter key-value pair (i.e `url.Values{}`) 
  - If reserved/special characters are url encoded then integrity of specially crafted payloads (lfi,xss,sqli) is lost.
  - `utils/url/URL` uses `utils/url/Params` to store/handle parameters and integrity of all such payload is preserved
  - `utils/url/URL` also provides options to customize url encoding using global variable and function params


- Parsing Unsafe/Invalid Paths
  - while parsing urls `url.Parse()` either discards or re-encodes some of the specially crafted payloads
  - If a non valid url encoding is given in url (ex: `scanme.sh/%invalid`) `url.Parse()` returns error and url is not parsed
  - Such cases are implicitly handled if `unsafe` is true
  
```
// Example urls for above condition
scanme.sh/?some'param=`'+OR+ORDER+BY+1--
scanme.sh/?some[param]=<script>alert(1)</script>
scanme.sh/%invalid/path
```

- `utils/url/URL` has some extra methods
  - `.TrimPort()`
  - `.MergePath(newrelpath string, unsafe bool)`
  - `.UpdateRelPath(newrelpath string, unsafe bool)` 
  - `.Clone()` and more


### Note

`utils/url/URL` embeds `url.URL` and thus inherits and exposes all `url.URL` methods and variables.
Its ok to use any method from `url.URL` (directly/indirectly) except `url.URL.Query()` and `url.URL.String()` (due to parameter encoding issues).
In any case if it is not possible to follow above point (ex: directly updating/referencing `http.Request.URL`) `.Update()` method should be called before accessing them which updates `url.URL` instance for this edgecase. (Not required if above rule is followed)
