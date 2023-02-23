# ProxyLogon
Original PoC: https://github.com/testanull

## How to use:
`python proxylogon.py <name or IP of server> <user@fqdn>`

### Example:

`python proxylogon.py primary administrator@lab.local`

If successful you will be dropped into a webshell. `exit` or `quit` to escape from the webshell (or ctrl+c)

By default, it will create a file `test.aspx`. This can be changed.

![](Images/screenshot.PNG)


### Support:

This project is not supported but PRs are open :)

### Special Thanks and resources:

@Flangvik
@Testanull
https://www.praetorian.com/blog/reproducing-proxylogon-exploit/


