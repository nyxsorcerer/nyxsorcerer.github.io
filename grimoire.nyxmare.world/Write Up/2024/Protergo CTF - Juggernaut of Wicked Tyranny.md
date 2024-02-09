---
tags:
  - CTF
  - protergo
  - jwt
  - reverse-engineering
  - c
title: Protergo CTF - [Juggernaut of Wicked Tyranny]
---
![[Screenshot 2024-02-09 at 04.09.29.png]]
# Prologue

An Individual local competition held by [Protergo](https://protergo.id/)company. The competition was starting from 1st February until 8th February. This competition is only limited to students.
# Write Up

## TL;DR Solution

1. Recovering the private key by reverse engineering the binary.
2. Making use of the private key to achieve privilege escalation by forging the JWT

## Detailed Explanation

It's a white box challenge, We were given the source code of the application.
![[Screenshot 2024-02-09 at 09.39.01.png]]

Looking at the `./application/app/Http/Controllers/HomeController.php`,
```php
<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;

use Tymon\JWTAuth\Facades\JWTAuth; //use this library
use Tymon\JWTAuth\Token;
use Tymon\JWTAuth\Exceptions\TokenExpiredException;
use Illuminate\Session\TokenMismatchException;

class HomeController extends Controller
{
    public function index(Request $request)
    {
        return view('login');
    }


    public function dashboard()
    {
        if (file_exists("/var/www/html/storage/jwt/private.pem")){
            return view('dashboard');
        }
        //[1]
        else{
            print_r(shell_exec("/var/www/html/storage/jwt/chall " . env('JWT_PASSPHRASE', '')));
        }
    }

    public function home(Request $request)
    {
        $flag = "";
        $rawToken = $request->cookie('auth');
        
        if($rawToken == ""){
            return redirect("/");
        }
        
        $token = new Token($rawToken);
        
        try{
        //[2]
            $payload = JWTAuth::decode($token);
            if ($payload->get('is_admin') == 1){
                $flag = "PROTERGO{FLAG}";
            }
        }
        catch(\Exception $e){
            return redirect("/");
        }

        return view('home', ['flag' => $flag]);
        
    }

    public function register(Request $request)
    {
        return view('register');
        
    }
}
```

The application attempts to execute the `chall` file with arguments taken from the environment variable `JWT_PASSPHRASE`[1]. 

After that, in the dashboard after authentication, there's a role check where players need to achieve privilege escalation[2] to get the flag.

![[Screenshot 2024-02-09 at 09.44.24.png]]
Analyzing the file it's a stripped ELF binary. 

So, I just put it into IDA and got the pseudocode of the file (below is a slightly modified variable name).
```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  int v4; // [rsp+10h] [rbp-F70h]
  int i; // [rsp+14h] [rbp-F6Ch]
  int j; // [rsp+18h] [rbp-F68h]
  int k; // [rsp+1Ch] [rbp-F64h]
  FILE *stream; // [rsp+28h] [rbp-F58h]
  int random_input_key[32]; // [rsp+30h] [rbp-F50h]
  int xor_key[32]; // [rsp+B0h] [rbp-ED0h]
  int expected_result[32]; // [rsp+130h] [rbp-E50h]
  char IV[16]; // [rsp+1B0h] [rbp-DD0h] BYREF
  char key[16]; // [rsp+1C0h] [rbp-DC0h] BYREF
  char dest[48]; // [rsp+1D0h] [rbp-DB0h] BYREF
  char format[3448]; // [rsp+200h] [rbp-D80h] BYREF
  unsigned __int64 v16; // [rsp+F78h] [rbp-8h]

  v16 = __readfsqword(0x28u);
  random_input_key[0] = 23;
  random_input_key[1] = 26;
  random_input_key[2] = 7;
  random_input_key[3] = 3;
  random_input_key[4] = 19;
  random_input_key[5] = 1;
  random_input_key[6] = 8;
  random_input_key[7] = 14;
  random_input_key[8] = 27;
  random_input_key[9] = 9;
  random_input_key[10] = 28;
  random_input_key[11] = 20;
  random_input_key[12] = 2;
  random_input_key[13] = 15;
  random_input_key[14] = 16;
  random_input_key[15] = 17;
  random_input_key[16] = 24;
  random_input_key[17] = 5;
  random_input_key[18] = 18;
  random_input_key[19] = 25;
  random_input_key[20] = 6;
  random_input_key[21] = 0;
  random_input_key[22] = 21;
  random_input_key[23] = 13;
  random_input_key[24] = 4;
  random_input_key[25] = 22;
  random_input_key[26] = 31;
  random_input_key[27] = 30;
  random_input_key[28] = 12;
  random_input_key[29] = 29;
  random_input_key[30] = 11;
  random_input_key[31] = 10;
  xor_key[0] = 231;
  xor_key[1] = 123;
  xor_key[2] = 105;
  xor_key[3] = 15;
  xor_key[4] = 54;
  xor_key[5] = 75;
  xor_key[6] = 1;
  xor_key[7] = 74;
  xor_key[8] = 193;
  xor_key[9] = 25;
  xor_key[10] = 56;
  xor_key[11] = 79;
  xor_key[12] = 23;
  xor_key[13] = 233;
  xor_key[14] = 160;
  xor_key[15] = 152;
  xor_key[16] = 196;
  xor_key[17] = 255;
  xor_key[18] = 64;
  xor_key[19] = 124;
  xor_key[20] = 120;
  xor_key[21] = 105;
  xor_key[22] = 69;
  xor_key[23] = 86;
  xor_key[24] = 73;
  xor_key[25] = 120;
  xor_key[26] = 150;
  xor_key[27] = 124;
  xor_key[28] = 252;
  xor_key[29] = 249;
  xor_key[30] = 79;
  xor_key[31] = 84;
  expected_result[0] = 215;
  expected_result[1] = 31;
  expected_result[2] = 95;
  expected_result[3] = 106;
  expected_result[4] = 84;
  expected_result[5] = 114;
  expected_result[6] = 50;
  expected_result[7] = 43;
  expected_result[8] = 160;
  expected_result[9] = 122;
  expected_result[10] = 93;
  expected_result[11] = 124;
  expected_result[12] = 36;
  expected_result[13] = 222;
  expected_result[14] = 196;
  expected_result[15] = 173;
  expected_result[16] = 240;
  expected_result[17] = 205;
  expected_result[18] = 35;
  expected_result[19] = 75;
  expected_result[20] = 27;
  expected_result[21] = 95;
  expected_result[22] = 32;
  expected_result[23] = 99;
  expected_result[24] = 127;
  expected_result[25] = 79;
  expected_result[26] = 247;
  expected_result[27] = 25;
  expected_result[28] = 201;
  expected_result[29] = 152;
  expected_result[30] = 44;
  expected_result[31] = 54;
  v4 = 0;
  qmemcpy(format, &unk_20C8, 3440uLL);
  if ( a1 > 1 )
  {
  //[3]
    strncpy(dest, a2[1], 0x21uLL);
    for ( i = 0; i <= 31; ++i )
    {
    //[4]
      if ( (xor_key[i] ^ dest[random_input_key[i]]) == expected_result[i] )
        ++v4;
    }
    if ( v4 == 32 )
    {
    //[5]
      for ( j = 16; j <= 31; ++j )
        IV[j - 16] = dest[j];
      for ( k = 0; k <= 15; ++k )
        key[k] = dest[k];
      puts("Passhprase correct!");
      puts("Private will be written on private.pem!");
      //[6]
      sub_13BE((__int64)format, 3440, (__int64)IV, (__int64)key, 0x10u);
      stream = fopen("/var/www/html/storage/jwt/private.pem", "w");
      fprintf(stream, format);
      fclose(stream);
    }
    else
    {
      puts("Passhprase incorrect!");
    }
    return 0LL;
  }
  else
  {
    puts("Usage: ./binary <passphrase>");
    return 0LL;
  }
}
```

Checking the main function, the logic is pretty simple. 

The binary will take the input from the argument and put it in the `dest` variable[3]. After that, there's a looping for 32 iterations, where each iteration will do the xor calculation. The calculation is xor-ing the value of `xor_key` and `dest[random_input_key]` and will validate with `expected_result`[4]. If all valid characters, it will split the `dest` variable into two pieces (each piece is 16 chars)[5].  After that, it will pass the input into the `sub_13BE` function[6].

```c
__int64 __fastcall sub_13BE(__int64 a1, int a2, __int64 a3, __int64 a4, unsigned int a5)
{
  __int64 v9; // [rsp+28h] [rbp-8h]

  v9 = mcrypt_module_open("rijndael-128", 0LL, &unk_2008, 0LL);
  if ( a2 % (int)mcrypt_enc_get_block_size(v9) )
    return 1LL;
  mcrypt_generic_init(v9, a4, a5, a3);
  mdecrypt_generic(v9, a1, (unsigned int)a2);
  mcrypt_generic_deinit(v9);
  mcrypt_module_close(v9);
  return 0LL;
}
```

With slight googling, I found the `sub_13BE` is very similar to this [Stackoverflow question](https://stackoverflow.com/questions/28477947/c-mcrypt-works-decrypt-not-using-rijndael-128-aes). Basically, this function will encrypt the `buffer` and the result will be written at `/var/www/html/storage/jwt/private.pem`.

To get the key, All need to do is just xor-ing the `xor_key` with the `expected_result`. So, I made the python script to do the automation.

```python
expected_result = []
expected_result.append(215)
expected_result.append(31)
expected_result.append(95)
expected_result.append(106)
expected_result.append(84)
expected_result.append(114)
expected_result.append(50)
expected_result.append(43)
expected_result.append(160)
expected_result.append(122)
expected_result.append(93)
expected_result.append(124)
expected_result.append(36)
expected_result.append(222)
expected_result.append(196)
expected_result.append(173)
expected_result.append(240)
expected_result.append(205)
expected_result.append(35)
expected_result.append(75)
expected_result.append(27)
expected_result.append(95)
expected_result.append(32)
expected_result.append(99)
expected_result.append(127)
expected_result.append(79)
expected_result.append(247)
expected_result.append(25)
expected_result.append(201)
expected_result.append(152)
expected_result.append(44)
expected_result.append(54)

xor_key = []
xor_key.append(231)
xor_key.append(123)
xor_key.append(105)
xor_key.append(15)
xor_key.append(54)
xor_key.append(75)
xor_key.append(1)
xor_key.append(74)
xor_key.append(193)
xor_key.append(25)
xor_key.append(56)
xor_key.append(79)
xor_key.append(23)
xor_key.append(233)
xor_key.append(160)
xor_key.append(152)
xor_key.append(196)
xor_key.append(255)
xor_key.append(64)
xor_key.append(124)
xor_key.append(120)
xor_key.append(105)
xor_key.append(69)
xor_key.append(86)
xor_key.append(73)
xor_key.append(120)
xor_key.append(150)
xor_key.append(124)
xor_key.append(252)
xor_key.append(249)
xor_key.append(79)
xor_key.append(84)

random_input_key = []
random_input_key.append(23)
random_input_key.append(26)
random_input_key.append(7)
random_input_key.append(3)
random_input_key.append(19)
random_input_key.append(1)
random_input_key.append(8)
random_input_key.append(14)
random_input_key.append(27)
random_input_key.append(9)
random_input_key.append(28)
random_input_key.append(20)
random_input_key.append(2)
random_input_key.append(15)
random_input_key.append(16)
random_input_key.append(17)
random_input_key.append(24)
random_input_key.append(5)
random_input_key.append(18)
random_input_key.append(25)
random_input_key.append(6)
random_input_key.append(0)
random_input_key.append(21)
random_input_key.append(13)
random_input_key.append(4)
random_input_key.append(22)
random_input_key.append(31)
random_input_key.append(30)
random_input_key.append(12)
random_input_key.append(29)
random_input_key.append(11)
random_input_key.append(10)

result = [None for x in range(0, 32)]
for a in range(0, 32):
    result[random_input_key[a]] = chr(xor_key[a] ^ expected_result[a])

print(''.join(result))
print(''.join(result)[:16], ''.join(result)[16:])
```

![[Screenshot 2024-02-09 at 10.11.34.png]]
![[Screenshot 2024-02-09 at 10.06.42.png]
![[Screenshot 2024-02-09 at 10.12.26.png]]

With this, the private key is already successfully recovered and all need to do is just forge the JWT to achieve privilege escalation.

I used the same technique at [[Protergo CTF - Just Wiggle Toes]] to forge the JWT.
```python
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import jwt, requests, re
pem_bytes = open('./private.pem', 'rb').read()
passphrase = open('./passphrase', 'rb').read().strip()

private_key = serialization.load_pem_private_key(
    pem_bytes, password=passphrase, backend=default_backend()
)

URL = "http://ctf.protergo.party:10004/"
encoded = jwt.encode({"iss":"http://jakarta.ctf.protergo.party:10003/api/portal_login","iat":1707296171,"exp":99999999999,"nbf":1707296171,"jti":"kKpu6PDBBCiuFhdA","sub":"29","prv":"3da04507aadf132cee732fdee4ef6aa390dec579","is_admin":1}, private_key, algorithm="RS256")

sess = requests.Session()
sess.get(f'{URL}')
res = sess.get(f'{URL}home', cookies={"auth": encoded})
r = re.compile(r'PROTERGO{.*}')
print(r.findall(res.text)[0])
```

![[Screenshot 2024-02-09 at 10.16.21.png]]

FLAG: `PROTERGO{673311e2d939238eaa08e461b0f4be5928293e26ac16ada1b5dbfed335c544b7}`