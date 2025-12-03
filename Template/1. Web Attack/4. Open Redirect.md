
- [ ] **Openredirex**
```bash
cat urls.txt | gf or | urldedupe | httpx-toolkit -t 200 | qsreplace FUZZ | openredirex -p test.txt -k FUZZ | grep '> https://google' | tee openredirex.txt 
```


- [ ]  **Nuclei**
```bash
cat urls.txt | gf redirect | uro | nuclei -t ~/nuclei-templates/coffinxp/openRedirect.yaml

cat urls.txt | grep '\?' | uro | nuclei -t ~/nuclei-templates/j4xx3n/or/open-redirect.yaml
```



