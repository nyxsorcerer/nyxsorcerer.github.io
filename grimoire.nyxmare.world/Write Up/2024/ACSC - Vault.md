---
title: ACSC - [Vault]
tags:
  - CTF
  - Write-up
  - acsc
  - hardware-hacking
  - side-channel
categories:
  - CTF
  - Write Up
---
![[Screenshot 2024-04-01 at 21.54.50.png]]
# Prologue
An online CTF competition by ACSC, this competition is qualification for competing in ICC for ASIA category.

![[dist-vault-bc8867dde0e36ae6cbd0e4c82707e2b78e4e5233.tar.gz]]
# Write Up
## TL;DR Solution

Exploiting side-channel attack to guess the PIN, if the PIN is correct it will delayed 100000ms.
## Detailed Explanation

### Initial Analysis

We were given a binary and a configuration server.

If we connecting into server, we can see that we only have a permission into executing the binary
![[Screenshot 2024-04-22 at 18.18.38.png]]

Looking at the `main` function, we can see that it will check the length of input, and then for every input characters will be xor-ed with the key. If it wrong, it will delayed for 100000ms.
![[Screenshot 2024-04-01 at 22.04.16.png]]

We can check all the possibility number 0-9. And then pick few samples and calculate the average. After that, check which numbers that get the longest time to execute.

Fortunately, the configuration already has a [time](https://man7.org/linux/man-pages/man1/time.1.html) command. We can make use of this command to get the time needed for execute without problem, even if we had a bad connection.
### Exploitation

```python
from pwn import *
import re 

p = remote('vault.chal.2024.ctf.acsc.asia', 9999)

TRIES = 10
KNOWN = ""

while len(KNOWN) != 10:
    times = {
        0: [],
        1: [],
        2: [],
        3: [],
        4: [],
        5: [],
        6: [],
        7: [],
        8: [],
        9: [],
    }
    for x in range(0, 10):
        for y in range(TRIES):
            p.sendlineafter('user@NSJAIL:/home/user$ ', "time ./chall")
            a = p.sendlineafter(b'Enter your PIN: ', f"{KNOWN}{str(x)*(10-len(KNOWN))}")
            p.recvline()
            p.recvline()
            p.recvline()
            a = p.recvline().decode().strip()
            r = re.compile("real\s+0m\d.\d+s")
            a = r.search(a).group().replace("real\t0m", "").replace("s", "")
            print(x, a)
            times[x].append(float(a))
    for x in range(10):
        avg = sum(times[x])/TRIES
        times[x] = avg
    m = str(max(times, key=times.get))
    print(m)
    KNOWN += m
    print(KNOWN)

avg_time = []

print(max(times, key=times.get))
```

After letting run for awhile, we get the PIN and the flag too.
![[Screenshot 2024-04-01 at 23.03.42.png]]

FLAG: `ACSC{b377er_d3L4y3d_7h4n_N3v3r_b42fd3d840948f3e}`







