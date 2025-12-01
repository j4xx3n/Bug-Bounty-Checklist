
- [ ] **JWT or Cookie Authentication**
- JWT's will never load cross origin.
- Cookie based authentication has potential for CSRF attack.
**Notes**
```

```
---


- [ ] **Graphql-Cop**
```bash
 python3 graphql-cop.py -t https://example.com/graphql -f | grep CSRF
```
**Notes**
```

```
---

- [ ] **Manual GET Request Test**
```http
?query=query{__typename}

https://example.com/graphql?query=query{__typename}
```
**Notes**
```

```
---

- [ ] **Manual URL Encoded Test**
- Change the `Content-Type` header and query to the following:
```http
Content-Type: application/x-www-form-urlencoded

query=query{__typename}
```
**Notes**
```

```
---

