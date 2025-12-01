
- [ ] Arjun 
```bash
cat urls.txt | grep '?' | urldedupe | cut -d '?' -f 1 | httpx-toolkit | sort -u | while read url; do arjun -u $url -m GET/POST -oT arjun.txt; done

sed -i 's/[[:space:]]\+?/?/' arjun.txt
```

- [ ] Paramspider
```bash
paramspider -d example.com

paramspider -l subs.txt

cat results/* > paramspider.txt && cd results/ && rm -rf *.txt
```


- [ ] ParamFinder
```bash
cat urls.txt | grep '?' | uro | cut -d '?' -f 1 | paramfinder -s -i | grep 'TRANSFORM_URL:' | cut -d ' ' -f 2 | anew paramfinder.txt
```

