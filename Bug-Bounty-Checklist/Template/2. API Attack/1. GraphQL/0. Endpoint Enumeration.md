
# **Found Endpoints**
```


```
---


- [ ] **Port Scan**
```bash
cat subs.txt | naabu -ports 80,443,8080,8443,3000,4000,5000,7000,8000,9000,1337,2020,2021,4500,5013 -o gqlPorts.txt
```
**Notes**
```

```
---

- [ ] **Endpoint Scan**
```bash
nuclei -list gqlPorts.txt -t ~/nuclei-templates/j4xx3n/graphql-endpoint-discovery.yaml

nuclei -list urls.txt -t ~/nuclei-templates/j4xx3n/graphql-introspection-detect.yaml
```
**Notes**
```

```
---

- [ ] **Search URLs Using Regex**
```bash
grep -Ei '(altair|api/(gql|graphiql|graphql)|graphql(\.php|/console|/schema\.(json|xml|yaml))?|playground|subscriptions|explorer|gql|graph)' urls.txt
```
**Notes**
```

```
---

- [ ] **InQL**
- Intercept traffic in burp suite with the InQL plugin and look for purple requests.
**Notes**
```

```
---


- [ ] **Search URLs for Hidden Endpoints**
- Filter the URLs to be only 3 directories deep with no parameters and run against nuclei.
```bash
cat live.txt | cut -d '?' -f1 | cut -d '/' -f1-5 | grep -v -i -E '\.(html|htm|php|asp|jpg|png|pdf|css|js|txt|xhtml|prf)([?#].*)?$' | grep '^http' | uro | nuclei -t ~/BugBounty/j4xx3n-nuclei-templates/graphql/graphql-endpoint-discovery2.yaml -rl 200
```
**Notes**
```

```
---


