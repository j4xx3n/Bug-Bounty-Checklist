
- [ ] Katana
```bash
katana -list subs.txt -o katana.txt

katana -list subs.txt -d 5 waybackarchive,commoncrawl,alienvault -kf -jc -fx -ef woff,css,png,svg,jpg,woff2,jpeg,gif,svg -o katana2.txt

katana -list subs.txt -hl -jc --no-sandbox -c 1 -p 1 -rd 3 -rl 5 -tlsi -o katana3.txt
```

- [ ] Waymore
```bash
echo example.com | waymore -mode U -oU waymore.txt

cat domains.txt | waymore -mode U -oU waymore.txt
```

- [ ] cURL Wayback Machine
```bash
curl -silent 'https://web.archive.org/cdx/search/cdx?url=*.example.com/*&collapse=urlkey&output=text&fl=original' | anew wayback.txt

cat domains.txt | while read i; do curl -silent 'https://web.archive.org/cdx/search/cdx?url=*.'$i'/*&collapse=urlkey&output=text&fl=original' | anew wayback.txt; done
```

- [ ] GAU
```bash
echo example.com | gau | anew gau.txt

cat subs.txt | gau | anew gau.txt
```


- [ ] URLFinder
```bash
echo example.com | urlfinder | anew urlfinder.txt

cat subs.txt | urlfinder | anew urlfinder.txt
```


- [ ] xurlfind3r
```bash
echo example.com | xurlfind3r | anew xurlfind3r.txt

cat subs.txt | xurlfind3r | anew xurlfind3r.txt
```


- [ ] xcrawl3r
```
echo example.com | xcrawl3r | anew xcrawl3r.txt

cat subs.txt | xcrawl3r | anew xcrawl3r.txt
```

- [ ] Galer
```bash
galer -u example.com | anew galer.txt

galer -u subs.txt | anew galer.txt
```


## **Scan JavaScript Files**

- [ ] Download JS files
`cat js.txt | while read i; do curl -O "$i"; done`

- [ ] Jsluice
`jsluice urls *.js | jq .url | grep http | cut -d '"' -f2 | sort -u jsluice.txt`


## **Filter Urls**

`cat urls/*.txt | cat all.txt | grep -a -E '^(https?://)?([^/]+\.)?example\.com'`| 

 