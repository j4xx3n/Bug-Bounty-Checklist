# References
https://www.youtube.com/watch?v=hDTZsx2Otgw&t=126s


# Instructions

## 1. Find New CVEs from Shodan
1. Use the folloing shodan dork with the vulnerable technology:
`product:"Grafana"`
2. Enter the following commands to downlaod the IPs  and domains:
```
1. Extract IPs and export to a text file  
var ipElements=document.querySelectorAll('strong');var ips=[];ipElements.forEach(function(e){ips.push(e.innerHTML.replace(/["']/g,''))});var ipsString=ips.join('\n');var a=document.createElement('a');a.href='data:text/plain;charset=utf-8,'+encodeURIComponent(ipsString);a.download='ip.txt';document.body.appendChild(a);a.click();  
  
2. Extract Doamins name and export to a text file  
var ipElements=document.querySelectorAll('strong'),ips=[],domains=[];ipElements.forEach(function(e){var t=e.innerHTML.replace(/['"]/g,'').trim();/^(\d{1,3}\.){3}\d{1,3}$/.test(t)?ips.push(t):/^(?!\d+\.)[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/.test(t)&&domains.push(t)});var dataString='IPs:\n'+ips.join('\n')+'\n\nDomains:\n'+domains.join('\n'),a=document.createElement('a');a.href='data:text/plain;charset=utf-8,'+encodeURIComponent(dataString);a.download='domains.txt';document.body.appendChild(a);a.click();
```
3. Run nuclei scan agains targets with tags or template specific to the CVE
`cat ip.txt | nuclei -tags grafana`
`cat domains.txt | nuclei -t cve-2025-12345.json`

## 2. Alienvault Scan
1. Get all results from alienvault for the target domain:
`./alienvault.sh example.com`

2. Scan with nuclei dast of manualy test parameters
`./alienvault.sh example.com | gf params | urldedupe | nuclei -dast`

## 3. Virus Total Scan
1. Get all results from virus total for the target domain:
`./virustotal.sh example.com`

2. Scan with nuclei dast of manualy test parameters
`./virustotal.sh example.com | gf params | urldedupe | nuclei -dast`


## 4. Wayback Scan
1. Get all results from the wayback machine for the target domain:
`./wayback.sh example.com`

2. Scan with nuclei dast of manualy test parameters
`./virustotal.sh example.com | gf params | urldedupe | nuclei -dast`

## 5. LostFuzzer
1. Use LostFuzzer agains the target domain to automate a nuclei dast scan
`./wayback.sh -d example.com`


## 6. Urlscan
1. Use urlscan to find hidden subdomains and urls
`python urlscan.py -d example.com --mode subdomains`
`python urlscan.py -d example.com --mode urls`

2. Sort parameters and scan with nuclei dast
`nuclei -list subdomains.txt -dast`