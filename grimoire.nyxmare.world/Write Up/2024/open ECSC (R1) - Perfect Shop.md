---
title: open ECSC (R1) - [Perfect Shop]
tags:
  - CTF
  - Write-up
  - web-exploitation
  - ecsc
  - client-side
  - xss
categories:
  - CTF
  - Write Up
drafta: "false"
---

![[Screenshot 2024-03-18 at 22.25.15.png]]
# Prologue
An online CTF competition by ECSC team. This competition held on March 18th until 24th March. This competition consists on 4 rounds (incl. final)

![[perfectshop.zip]]
# Write Up
## TL;DR Solution

A vulnerability exists in package `"perfect-express-sanitizer": "^1.0.13"`. In the `whitelist` feature, this package checking the whole URL (Including query params) instead of the path only. Therefore, by putting the whitelisted path in the query params, the XSS will be triggered.

## Detailed Explanation

### Initial Analysis

We were given a source code that has a tree directory like this.

![[Screenshot 2024-04-19 at 00.45.14.png]]

```js
app.post('/report', (req, res) => {
    // 8< -- snip - snip -- >8
    fetch(`http://${HEADLESS_HOST}/`, { 
        method: 'POST', 
        headers: { 'Content-Type': 'application/json', 'X-Auth': HEADLESS_AUTH },
        body: JSON.stringify({ 
            actions: [
                {
                    type: 'request',
                    url: `http://${WEB_DOM}/`,
                },
                {
                    type: 'set-cookie',
                    name: 'flag',
                    value: FLAG
                },
                {
                    type: 'request',
                    url: `http://${WEB_DOM}/product/${req.body.id}`
                },
                {
                    "type": "sleep",
                    "time": 1
                }
            ]
         })
    }
    // 8< -- snip - snip -- >8
});
```

By reading the source code in `server.js`, The flag location is in the cookie. So, i assume this is a XSS challenge.

By default, in EJS the HTML is escaped, unless it using this opening tags `<%-` for printing the value [^1]. So, we can search the template file that using that feature and the value that we can control.

```html
<%- include('header') %>

<h1>Searching for "<%- query %>"</h1>

<%- include('product_list', { products: products }) %>

<%- include('footer') %>
```



### Exploitation



[^1]: https://ejs.co/#:~:text=%3C%25%2D%20Outputs%20the%20unescaped%20value%20into%20the%20template

