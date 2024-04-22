---
title: ACSC - [An4lyz3_1t]
tags:
  - CTF
  - Write-up
  - acsc
  - hardware-hacking
  - logic-analyzer
  - serial-connection
  - signal-connection
categories:
  - CTF
  - Write Up
---
![[Screenshot 2024-04-22 at 20.42.24.png]]
# Prologue
An online CTF competition by ACSC, this competition is qualification for competing in ICC for ASIA category.

![[dist-an4lyz3-1t-6a4bd1d579977d0a56333810ceafd835d780ac0c.tar.gz]]
# Write Up

## Initial Analysis

We were given a file

![[Screenshot 2024-04-22 at 20.44.43.png]]

If we looking at the description, we can have an information about this challenge.
- The file is a serial logs and we can use `Saleae Logic Analyzer`
- The flag is in signal connection

By using google-fu, I can find the similar challenge with HTB - Serial Logs. [anniequus.com](https://anniequus.com/posts/htb-hardware-writeups/). 

## Exploitation

In the writeup, it mention that he got the correct bitrate by brute-forcing the bitrate from this article [www.engineersgarage.com](https://www.engineersgarage.com/raspberrypi/raspberry-pi-serial-communication-uart-protocol-ttl-port-usb-serial-boards/) . And I did the same, until I found a correct bitrate `57600 bps`. 

![[Screenshot 2024-04-22 at 21.21.06.png]]

I put the async serial analyzer in channel 4 with those configuration.

![[Screenshot 2024-04-22 at 21.21.54.png]]

By changing the data view into terminal, i managed get the flag.

FLAG: `ACSC{b4by4n4lyz3r_548e8c80e}`







