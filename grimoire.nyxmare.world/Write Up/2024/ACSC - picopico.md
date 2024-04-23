---
title: ACSC - [picopico]
tags:
  - CTF
  - Write-up
  - acsc
  - hardware-hacking
  - reverse-engineering
categories:
  - CTF
  - Write Up
---
![[Screenshot 2024-04-22 at 21.26.07.png]]
# Prologue
An online CTF competition by ACSC, this competition is qualification for competing in ICC for ASIA category.

![[dist-picopico-18a7c81b205ca1de2d152cdbef6a0cb525bdf433.tar.gz]]
# Write Up

## Initial Analysis

We were given one file, a `firmware.bin` file
![[Screenshot 2024-04-23 at 11.15.59.png]]

Since We don't know what file is this, we can use binwalk to extract the data.
![[Screenshot 2024-04-23 at 12.06.57.png]]

After analyzing each file, i found a suspicious file where there's look like an obfuscated script and the spacing is a little bit different with others.
![[Screenshot 2024-04-23 at 12.08.03.png]]

According to the documentation[^1], `microcontroller.nvm` is a module to store raw bytes in the reserved section volatile memory.

Basically, this source above is about a writing command in cmd. The flow of source code is like this:
- Checking the first four byte of the memory as signature 
- Do a xor encryption between variable `O` and `h`.  
	- Where `O` is the index memory from `0x4` until `47`
	- Where `h` is the index memory from `47` until `90`
- After that, it will write the result of encryption into windows `cmd`.

## Exploitation

After stuck for awhile where to find the value of memory, I decide to read the description challenge again. It did mention the file w as a `firmware dump`. So I decide to analyze file again and I did really find the signature.
![[Screenshot 2024-04-23 at 12.27.49.png]]

After that, I create a script to parse the dump file and do decryption according to the malware before and finally I can get the flag.

```python
fa = open("firmware.bin", 'rb')
zz = fa.read()
s_idx = zz.find(b"\x10\x53\x7f\x2b")

a=0x04
K=43

O = []
for __ in range(s_idx+a, s_idx+a+K):
    O.append((zz[__]))

h = []
for __ in range(s_idx+a+K, s_idx+a+K+K):
    h.append((zz[__]))

F=bytes((kb^fb for kb,fb in zip(O,h))).decode()
# print(O, h)
print(F)
```


![[Screenshot 2024-04-23 at 12.30.30.png]]

FLAG: `ACSC{349040c16c36fbba8c484b289e0dae6f}`

[^1]: https://docs.circuitpython.org/en/latest/shared-bindings/nvm/index.html 





