---
layout: post
title: "Issue Certificate at Let's Encrypt"
description: "Issue Certificate at Let's Encrypt"
categories: SSL, HTTPS, Setting, Certificate

---

Introduce how to issue certificate for encrypting server as ssl.

It is based on `Ubuntu 19.04`.

## Install Let's Encrypt
```bash
git clone https://github.com/letsencrypt/letsencrypt
./letsencrypt-auto --help
./letsencrypt-auto certonly --manual
```
If you try to acme-challenge and use nginx in server, you must change Nginx configure.

Because it try to access `.well-known/acme-challenge`.

But, Nginx denies to directory name or file name containing .(dot).

So, change Nginx configure.

## acme-challenge
After execute command `./letsencrypt-auto certonly --manual`, set nginx config.

Here is sample config for nginx.

```
server {
	server_name [domain];
	listen 80 default_server;
	listen [::]:80 default_server;
	root /var/www/html;
	index index.html index.htm index.nginx-debian.html;

	location ~ /\.well-known {
		#allow all;
		root /var/www/letsencrypt;
	}
	location / {
		try_files $uri $uri/ =404;
	}
}
```
Nginx restart using execute `service nginx restart` or `service nginx reload`.

Next, make a folder `.well-known/acme-challenge` and make acme-challenge file conatains contents.

In sample case, acme-challenge is `/var/www/letsencrypt/.well-known/acme-challenge/~~~`.

Finally you can get certificates for your server at `/etc/letsencrypt/live/[domain]/*.pem`.

## HTTP2 on SSL in Nginx
```
server{
	server_name [domain];
	listen 443 ssl http2 default_server;
	listen [::]:443 ssl http2 default_server ipv6only=on;
	ssl_certificate /etc/letsencrypt/live/[domain]/fullchain.pem;
	ssl_certificate_key /etc/letsencrypt/live/[domain]/privkey.pem;
	ssl_trusted_certificate /etc/letsencrypt/live/[domain]/fullchain.pem;
    
    root /var/www/html;

	location / {
                try_files $uri $uri/ =404;
        }
}
```
Nginx restart using execute `service nginx restart` or `service nginx reload`.

Now, you can access your server as `https`.

## Resource 
http://blog.kimgihong.com/devlog/AWS_EC2_letsencrypt_SSL