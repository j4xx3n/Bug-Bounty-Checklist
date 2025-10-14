
## **Gather Links**
**cURL**
```bash
cat urls.txt | xargs -P 10 -I {} curl -s {} | grep -oP 'href=["\x27]\K[^"\x27]*' | anew links.txt
```

**FFUF**💯
```bash
cat urls.txt | ffuf -w - -u FUZZ -mr 'href=["'\'']([^"'\'']*)["'\'']' -s -or | tee links.txt
```

## **Filter External 404 Links**

**Expired/Unclaimed Domains**
```bash
cat links.txt | grep -v 'example.com' | cut -d '/' -f 3 | rev | cut -d. -f1,2 | rev | sort -u | httpx-toolkit -mc 404
```

**Social Media**
```bash
cat links.txt | grep -E 'facebook\.com|x\.com|instagram\.com|linkedin\.com|github\.com'
```

## **One Liner**🔥

```bash
cat urls.txt | ffuf -w - -u FUZZ -mr 'href=["'\'']([^"'\'']*)["'\'']' -s -or | grep -v 'example.com' | httpx-toolkit -mc 404
```



## **Refrences**

- [BePractical](https://www.youtube.com/watch?v=eRwqlVF0Rp4)
