---
name: component-vuln-intel
description: >-
  Online intelligence gathering: after identifying a component, mandatory CVE / search engine / Chinese security community / GitHub PoC / asset engine / real-time intelligence / dependency expansion, and rerouting when blocked. Use when a framework/component/version is identified and must be searched before exploitation.
metadata:
  tags: [penetration-testing, penetration-testing, red-team]
---

## Online Intelligence Gathering (identify component → search the whole internet immediately; results = leads / tentative, not confirmed Facts until verified)

```
🔴 Once a framework / component / version is identified → you must stop local scanning and search online immediately (exploiting without searching = blind shooting = violating the iron rules).
🔴 Execute the entire sequence below (not optional). Replace {C} = component name, {V} = version. Every step must actually be executed with browser_navigate or terminal:

1. CVE vulnerability databases (mandatory, to find known vulnerabilities):
  terminal: searchsploit {C} {V}
  terminal: curl -s "https://cve.circl.lu/api/search/{C}/{V}" | python3 -c "import sys,json;[print(x['id'],x.get('summary','')[:80]) for x in json.load(sys.stdin)[:10]]"
  browser_navigate: https://github.com/advisories?query={C}+{V}
  browser_navigate: https://www.cvedetails.com/google-search-results.php?q={C}+{V}&sa=Search

2. Search engines (run at least 3, to find vulnerability analysis + PoCs):
  browser_navigate: https://www.google.com/search?q={C}+{V}+exploit+PoC+RCE+site:github.com
  browser_navigate: https://www.google.com/search?q={C}+{V}+vulnerability+exploit+reproduction
  browser_navigate: https://www.baidu.com/s?wd={C}+{V}+vulnerability+exploit+poc+getshell
  browser_navigate: https://www.bing.com/search?q={C}+{V}+CVE+exploit+poc
  browser_navigate: https://duckduckgo.com/?q={C}+{V}+vulnerability+exploit

3. Chinese security communities (mandatory; Chinese-language first disclosures are numerous and analysis is often deep):
  browser_navigate: https://xz.aliyun.com/search?keyword={C}+vulnerability
  browser_navigate: https://www.seebug.org/search/?keywords={C}
  browser_navigate: https://paper.seebug.org/search/?keyword={C}
  browser_navigate: https://www.freebuf.com/search?search={C}+{V}
  browser_navigate: https://ti.qianxin.com/vulnerability?keyword={C}
  browser_navigate: https://www.anquanke.com/search?s={C}

4. GitHub search for PoC / exploit code (mandatory; the most direct way to get exploit code):
  terminal: curl -s "https://api.github.com/search/repositories?q={C}+{V}+exploit+OR+poc+OR+CVE&sort=updated&per_page=10" | python3 -c "import sys,json;d=json.load(sys.stdin);[print(x['full_name'],x['html_url'],x.get('description','')[:60]) for x in d.get('items',[])]"
  terminal: curl -s "https://api.github.com/search/code?q={C}+RCE+OR+shell+OR+exploit+language:python&per_page=5" | python3 -c "import sys,json;d=json.load(sys.stdin);[print(x['html_url']) for x in d.get('items',[])]"
  terminal: curl -s "https://api.github.com/search/repositories?q={C}+CVE&sort=stars&per_page=5" | python3 -c "import sys,json;d=json.load(sys.stdin);[print(x['full_name'],x['stargazers_count'],'★',x.get('description','')[:50]) for x in d.get('items',[])]"
  After finding a repository: curl -s "https://api.github.com/repos/{owner}/{repo}/readme" | python3 -c "import sys,json,base64;print(base64.b64decode(json.load(sys.stdin)['content']).decode())"

5. Asset engines (find similar targets / exposure surface):
  browser_navigate: https://fofa.info/result?qbase64=$(echo -n 'app="{C}"' | base64)
  browser_navigate: https://www.shodan.io/search?query={C}+{V}
  browser_navigate: https://www.zoomeye.org/searchResult?q={C}
  browser_navigate: https://search.censys.io/search?resource=hosts&q=services.software.product:{C}

6. Real-time intelligence (latest 0-days / in-the-wild exploitation):
  browser_navigate: https://x.com/search?q={C}+CVE+OR+0day+OR+exploit&f=live
  browser_navigate: https://www.reddit.com/r/netsec/search/?q={C}&sort=new&t=month
  browser_navigate: https://www.exploit-db.com/search?q={C}

7. Dependency expansion (mandatory): after searching {C}, extract its dependency manifest (package.json / pom.xml / requirements.txt / go.mod) → repeat 1-6 for each dependency

🔴 Handling blocked searches (on 403 / CAPTCHA / empty results / timeout → execute in order, do not give up):
  ① Change UA: curl -H "User-Agent: Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)" "{URL}"
  ② Jina reader: browser_navigate: https://r.jina.ai/{original URL}
  ③ Google cache: browser_navigate: https://webcache.googleusercontent.com/search?q=cache:{domain}+{keyword}
  ④ Archive: browser_navigate: https://web.archive.org/web/{URL}
  ⑤ GitHub API alternative (GitHub pages are blocked but the API is not): use the curl commands from step 4 above
  ⑥ Switch engines: Google blocked → run Bing / DuckDuckGo / Baidu; Baidu blocked → run Google / Bing
  ⑦ Use a proxy: obtain a SOCKS5 proxy per the `proxy-tool-bootstrap` sequence and retry
  If everything is blocked and there are still no results → write a negative Fact "searched {C} {V} across all channels; no public vulnerabilities" → switch to `zero-day-discovery`
```
