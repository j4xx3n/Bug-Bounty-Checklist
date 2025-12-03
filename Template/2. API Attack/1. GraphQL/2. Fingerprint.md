
## **GraphQL Server Fingerprinting**

- [ ] **Graphw00f**
```bash
python3 main.py -f -t https://example.com/graphql
```

- [ ] **Known Vulnerabilities**
```



```

**Notes**
```

```
---

## **Detecting the Authentication Layer**

- [ ] Send an unauthenticated introspection query and check for the following errors:

| **Error message**                                                                                          | **Possible authentication implementation** |
| ---------------------------------------------------------------------------------------------------------- | ------------------------------------------ |
| Authentication credentials are missing.         Authorization header is required and must contain a value. | OAuth 2.0 Bearer with JSON Web Token       |
| Not Authorised!                                                                                            | GraphQL Shield                             |
| Not logged in Auth required API key is required                                                            | GraphQL Modules                            |
| Invalid token!                                                       Invalid role!                         | graphql-directive-auth                     |
**Notes**
```

```
---

