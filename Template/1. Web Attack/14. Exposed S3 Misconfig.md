
## **Manual**

- [ ] **Append /%c0**
```bash
cat subs.txt | while read i; do echo "$i/%c0"; done | httpx-toolkit -silent -ms "<Error>" 
```

- [ ] **Httpx-toolkit**
```bash
cat subs.txt | httpx-toolkit -cl -ip -sc -td -server -title | grep S3 | cut -d" " -f1
```

## **Automated**

- [ ] **Nuclei**
```bash

```