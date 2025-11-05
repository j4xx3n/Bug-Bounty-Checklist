
- We can determine a users state based on the status code that is returned from a cross site request.
- For example if https://example.com/account/messages returns a 200 if provided the correct auth cookie but returns a 403 if it is not provided.
- We can use this anomoly to determin if the user has an active session on the site.
- You can create a link in your html code that will display if the url loaded or was given an error.
- If the url gets an error it means to request got either a 4xx or 5xx status code
- If the url loads with onload it mean it got a 2xx or 3xx status code

![[Pasted image 20250925152014.png]]