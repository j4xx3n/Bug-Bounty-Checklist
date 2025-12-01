
**Note: It is better to gather authenticated endpoints for this attack. Try signing up and proxy traffic.**


- [ ] **Nuclei Scan**
```bash
cat urls.txt | httpx-toolkit -silent -mc 200 | nuclei -t nuclei-templates/vulnerabilities/cors/ -o cors_results.txt
```

- [ ] **Manual Scan**
```bash
cat urls.txt | httpx-toolkit -silent -mc 200 | while read i; do curl -H "Origin: http://evil.com" -I $i | grep -i -e "access-control-allow-origin" -e "access-control-allow-methods" -e "access-control-allow-credentials"; done
```

