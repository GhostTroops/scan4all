# urlutil
The package contains various helpers to interact with URLs


## URL Parsing Methods

 Function                                            | Description                                      | Type                          | Behavior                                 |
-----------------------------------------------------|--------------------------------------------------|-------------------------------|------------------------------------------|
 `Parse(inputURL string)`                            | Standard URL Parsing (+ Some Edgecases)          | Both Relative & Absolute URLs | NA                                       |
 `ParseURL(inputURL string, unsafe bool)`            | Standard + Unsafe URL Parsing (+ Edgecases)      | Both Relative & Absolute URLs | NA                                       |
 `ParseRelativeURL(inputURL string, unsafe bool)`    | Standard + Unsafe URL Parsing (+ Edgecases)      | Only Relative URLs            | error if absolute URL is given           |
 `ParseRawRelativeURL(inputURL string, unsafe bool)` | Standard + Unsafe URL Parsing                    | Only Relative URLs            | error if absolute URL is given           |
 `ParseAbsoluteURL(inputURL string, unsafe bool)`    | Standard + Unsafe URL Parsing (+ Edgecases)      | Only Absolute URLs            | error if relative URL is given           |

### Known Edgecases / Changes from `url.URL`

- Query Parameters are Ordered
- Invalid unicode characters and invalid url encodings allowed in unsafe mode
- `u.Path` is always `/` prefixed if not empty (Except `ParseRawRelativePath`)
- allows invalid values / encodings in url path
- Does not encode characters except reserved characters in query parameters (see: Raw Params)
- almost proper parsing of url into parts (scheme,host,path,query,fragment) [known limitation of manually added hostnames like mydomain (without `.` in hostname)]


> More details on each edgecase/behavior is given below

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

- Dealing with Double URL Encoding of chars like `%0A` when `.Path` is directly updated

    when `url.Parse` is used to parse url like `https://127.0.0.1/%0A` it internally calls `u.setPath` which decodes `%0A` to `\n` and saves it in `u.Path` and when final url is created at time of writing to connection in http.Request Path is then escaped again thus `\n` becomes `%0A` and final url becomes `https://127.0.0.1/%0A` which is expected/required behavior.

    If `u.Path` is changed/updated directly after `url.Parse` ex: `u.Path = "%0A"` then at time of writing to connection in http.Request, Path is escaped again thus `%0A` becomes `%250A` and final url becomes `https://127.0.0.1/%250A` which is not expected/required behavior to avoid this we manually unescape/decode `u.Path` and we set `u.Path = unescape(u.Path)` which takes care of this edgecase.

    This is how `utils/url/URL` handles this edgecase when `u.Path` is directly updated.

### Note

`utils/url/URL` embeds `url.URL` and thus inherits and exposes all `url.URL` methods and variables.
Its ok to use any method from `url.URL` (directly/indirectly) except `url.URL.Query()` and `url.URL.String()` (due to parameter encoding issues).
In any case if it is not possible to follow above point (ex: directly updating/referencing `http.Request.URL`) `.Update()` method should be called before accessing them which updates `url.URL` instance for this edgecase. (Not required if above rule is followed)

