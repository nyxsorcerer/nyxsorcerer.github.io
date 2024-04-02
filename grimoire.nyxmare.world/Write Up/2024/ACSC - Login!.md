---
title: ACSC - [Login!]
tags:
  - CTF
  - Write-up
  - web-exploitation
  - acsc
  - server-side
  - nodejs
categories:
  - CTF
  - Write Up
---
![[Screenshot 2024-03-31 at 18.50.44.png]]
# Prologue
An online CTF competition by ACSC, this competition is qualification for competing in ICC for ASIA category.

![[login-web.tar.gz]]
# Write Up
## TL;DR Solution

The player sends array with guest value in username, the role check is strict-comparison of string "guest", but the input is an array with guest value. This happen because there's no check for type.
## Detailed Explanation

### Initial Analysis

We were given a simple server-side nodejs.

```js
// ./app.js
// 8< -- snip - snip -- >8
const USER_DB = {
    user: {
        username: 'user', 
        password: crypto.randomBytes(32).toString('hex')
    },
    guest: {
        username: 'guest',
        password: 'guest'
    }
};
// 8< -- snip - snip -- >8

app.post('/login', (req, res) => {
    const { username, password } = req.body; //[1]
    if (username.length > 100) return res.send('Username is too long');

    const user = USER_DB[username]; //[2]
    if (user && user.password == password) {
        if (username === 'guest') { //[3]
            res.send('Welcome, guest. You do not have permission to view the flag');
        } else {
            res.send(`Welcome, ${username}. Here is your flag: ${FLAG}`);
        }
    } else {
        res.send('Invalid username or password');
    }
});

// 8< -- snip - snip -- >8
```

We can control the `username`, and `password` variable. And there's no type check in this variable. Which mean, we can input a an object or array [1].  

After that, the variable username is being used as key to access credentials in `USER_DB` variable [2]. So, when we input `guest` it will access the credentials with key `guest`. Our goals is to have access a non-guest user. But the password of `user` is being randomized and impossible to brute-force.

In javascript, when we access a key of object, the `key input` will be do a pre-processing into `.toString()` first. 
![[Screenshot 2024-03-31 at 18.39.13.png]]

### Exploitation

Fortunately, our input doesn't sanitized, and we can input an array in variable username [1]. By sending an `guest` array in requests, the `username` variable is an array and it will do a role check, a strict-comparison with string `guest`. Which mean it will return a `false`

![[Screenshot 2024-03-31 at 18.48.07.png]]

FLAG: `ACSC{y3t_an0th3r_l0gin_byp4ss}`







