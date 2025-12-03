
- **I used AI to create some of this content. It is not yet verified.**

## **🔐 Broken Authentication & Session**

- Cleartext transmission of session token
	- Log in to site with burp, browse the entire site and check for and session cookies sent over HTTP.
	- Test if site can be accessed through HTTP, login, browse the entire site and check for and session cookies sent over HTTP.
    
- Failure to invalidate session on logout
	- Log out and try to use the old session.
    
- Failure to invalidate session on password reset/change
	-  Reset password and try to use the old session.
    
- Weak login function (over HTTP)
	- Test if login function uses HTTP
	- Test if site can be accessed through HTTP and test login function
    
- Weak registration (over HTTP)
	- Test if signup function uses HTTP. (Check if the token is sent over HTTP)
	- Test if password reset uses HTTP.
	- Test if site can be accessed through HTTP and test signup and password reset.
    

## **🔓 Broken Access Control (BAC)**

- Bypass of password confirmation (change-password endpoint pattern)
	- Login and check it you need to any extra verification to reset password
	- Reference: https://github.com/FlowiseAI/Flowise/security/advisories/GHSA-fjh6-8679-9pch
    
- Username/email enumeration (non-bruteforce via response differential)

## **🌐 Server Security Misconfiguration**

- CAPTCHA implementation flaw (detectable only if static or bypassable)
    - Attempt to bypass baptcha
    - Reference: https://medium.com/@mtsboysquad001/captcha-bypass-28de7279865b
- Clickjacking on sensitive action (X-Frame-Options missing)
    - Find pages with sensitive buttons and check for missing X-Frame-Options header.

- DBMS misconfiguration: excessively privileged error pages

- Lack of password confirmation on delete account
	- Check if you can delete your account without the password or any other confirmation.

- Missing Cache-Control header on sensitive pages
	- Find sesitive pages and check for lack of Cache-Control header
    
- Mail server misconfiguration – DMARC missing
	- Run all domains and subdomains with an MX record through dmarcian.
    
- DNS zone transfer enabled
	- Attempt a zone transfer on all ns records
    
- Missing Secure/HTTPOnly cookie flags
	- Look for `; secure` & `; HttpOnly` in the Set-Cookie response header.
    
- No rate limiting (login, register, email trigger, SMS trigger)
	- Check for rate limit with `curl --rate`

- OAuth misconfiguration: account squatting (requires URL pattern checking)
	1: Signup for victim using email signup  
	2: Signup through google login using the same email  
	3: The user will be logged in  
	4: This vulnerability is very high severity because of exploitation and complete account access if the victim creates an account.
    
- WAF bypass via direct server access (detect alternative hostnames)
    - Attempt to find origin IP address. 
    - Don't report. Testing origin IP bypasses WAF protection.

## **📤 Sensitive Data Exposure**

- Token in URL (user-facing endpoints reveal token)
	- find session token and grep for it in all urls.
	- Reference: https://medium.com/@jaycees10000/session-token-in-url-11e85b613010
    
- Token leakage via Referer over HTTP
	- Create reset password link and click it.
	- Try to navigate to an http site and check if the token is in the referer header.
    
- Token leakage via Referer to untrusted 3rd-party
	- Create reset password link and click it.
	- Click the twitter/facebook/linkedin icons and capture requests
	- Check if the password reset token is being sent to one of these sites via the Referer header.
    
- localStorage/sessionStorage containing sensitive tokens (detectable via JS file scanning)
    
- Visible detailed error/debug page
    
- Password reset token sent over HTTP
	- Check if password reset is sent over HTTP ot HTTPS
    
- EXIF geolocation not stripped
    1) Got to Github ( [https://github.com/ianare/exif-samples/tree/master/jpg](https://github.com/ianare/exif-samples/tree/master/jpg))  
	2) There are lot of images having resolutions (i.e 1280 * 720 ) , and also whith different MB’s
	3) Go to Upload option on the website  
	4) Upload the image  
	5) see the path of uploaded image ( Either by right click on image then copy image address OR right click, inspect the image, the URL will come in the inspect , edit it as html )  
	6) open it ([http://exif.regex.info/exif.cgi](http://exif.regex.info/exif.cgi))  
	7) See wheather is that still showing exif data , if it is then Report it.

## **🛜 Insecure Data Transport / Storage**

- Executable download with no integrity check (detect missing checksum/signature)
	- look for the ability to download an executable without a checksum
    
- Sensitive app data stored unencrypted externally (if downloadable)
    
- Server-side credentials stored plaintext (requires known endpoint)
	- Look for credentials stored in plain text being sent in http traffic.
    

## **🧱 Cloud / API Security**

- Misconfigured APIs – insecure endpoints (publicly exposed admin/debug endpoints)
	- Look for exposed S3 buckets with full control for all users.

## **🧬 Cross-Site Scripting**

- Data URI XSS
    
- Referer-based XSS
    
- Stored XSS (difficult but doable with controlled payload)
    
- UXSS indicators (limited, browser-dependent)
    

## **🪞 Server-Side Injection**

- Email HTML injection
	- Test if you can modify any values in an email sent from the application.
	- Test changing this value to an HTML injection.
    
- External authentication injection
	- 

- SSTI (basic payload tests)
    

## **🔐 Cryptographic Weakness (Web-detectable only)**

- Use of vulnerable crypto library (detectable via JS fingerprinting)
    
- Expired certificate
	- Check if any sites have expired certs
    
- Weak PRNG patterns in JS (limited cases)
    
- Predictable IV (if exposed in API responses)
    

_(Excluded deep crypto items like side-channel attacks, PRNG seed size, etc.)_

## **🧩 Insufficient Security Configurability**

- No password policy (detect via weak password acceptance)
	- Check if you can set your password to anything/very weak password.
    
- Weak password-reset flow (token not invalidated after use)
	- Check if password reset token can be used multiple times.
    
- Weak 2FA implementation (token remains obtainable)
    
- 2FA secret cannot be rotated (if API reveals secret)
    

