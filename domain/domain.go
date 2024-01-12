package main

// This document is Licensed under Creative Commons CC0.
// To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring rights
// to this document to the public domain worldwide.
// This document is distributed without any warranty.
// You should have received a copy of the CC0 Public Domain Dedication along with this document.
// If not, see https://creativecommons.org/publicdomain/zero/1.0/legalcode.


// Usage with generating
//
// dnf update
// dnf install epel-release
// dnf install nginx certbot python3-certbot-apache mod_ssl python3-certbot-dns-digitalocean python3-certbot-dns-digitalocean python3-certbot-nginx
// firewall-cmd --permanent --add-port=80/tcp --zone=public
// firewall-cmd --permanent --add-port=443/tcp --zone=public
// firewall-cmd --reload
// certbot certonly --standalone -d example.com
// cp /etc/letsencrypt/live/example.com/privkey.pem /etc/ssl/tig.key
// cp /etc/letsencrypt/live/example.com/fullchain.pem /etc/ssl/tig.crt

// go run domain/domain.go
