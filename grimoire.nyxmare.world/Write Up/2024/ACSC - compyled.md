---
title: ACSC - [compyled]
tags:
  - CTF
  - Write-up
  - acsc
  - reverse-engineering
  - python-bytecode
categories:
  - CTF
  - Write Up
---
![[Screenshot 2024-04-22 at 23.05.26.png]]
# Prologue
An online CTF competition by ACSC, this competition is qualification for competing in ICC for ASIA category.

![[dist-compyled-cd28f1dad3613ce9587e7d963cd82bff95c8156b.tar.gz]]
# Write Up

## Initial Analysis

We were given only one file pyc
![[Screenshot 2024-04-22 at 23.07.48.png]]

Using `uncompyle` to get the original source doesn't work due to the unsupported version. And this has the same case with `pycdc` too.
![[Screenshot 2024-04-23 at 11.01.04.png]]

Well, Since we still can run the script, we can run it under `ltrace` and get the history call from memory dump.

## Exploitation

We can use `-s` argument for preventing `ltrace` to truncate the string
![[Screenshot 2024-04-23 at 12.58.19.png]]

FLAG: `ACSC{d1d_u_notice_the_oob_L04D_C0N5T?}`







