package main

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

// This document is Licensed under Creative Commons CC0.
// To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring rights
// to this document to the public domain worldwide.
// This document is distributed without any warranty.
// You should have received a copy of the CC0 Public Domain Dedication along with this document.
// If not, see https://creativecommons.org/publicdomain/zero/1.0/legalcode.

// tig is a low complexity git competitor.
// The main design decision is to let the client deal with ordering and tagging.
// This makes the server side and the protocol simple.
// Each repository can contain files from multiple projects.
// Any repeated patterns can be compressed at the file system level.

// Storage directory. Suggestions:
// /tmp It cleans up fast, it is sometimes low latency memory based storage.
// /usr/lib It is a good choice for executable modules. It is persistent.
// /var/log Choose this for persistent data. It is persistent across reboots.
// /opt/ Use this for entire solutions. It is persistent.
// ~/ Use, if you run outside a container without privileges, but you need persistence across reboot.
// It is a good idea to delayed delete files setting `cleanup`.
// Clients can keep resubmitting them making the system more resilient.
// Such systems comply easier with privacy regulations being just a cache not a root storage.

var root = "/tmp"
var cleanup = 10 * time.Minute

const MaxFileSize = 128 * 1024 * 1024

var noAuthDelay sync.Mutex

// Usage
//
//echo test > /tmp/test
//echo abc > /tmp/apikey
//curl 127.0.0.1:7777/?apikey=abc
//curl -X PUT 127.0.0.1:7777/?apikey=abc -T /tmp/test
//curl -X POST 127.0.0.1:7777/?apikey=abc -T /tmp/test
//curl 127.0.0.1:7777/?apikey=abc
//curl 127.0.0.1:7777/f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2.tig?apikey=abc
//cat /tmp/test | sha256sum | head -c 64
//printf "http://127.0.0.1:7777/`cat /tmp/test | sha256sum | head -c 64`.tig"

// Usage with generating certificates. Please review any firewall policies.
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

func main() {
	if len(os.Args) == 4{
		f, _ := os.ReadFile(os.Args[1])
		f = bytes.ReplaceAll(f, []byte(os.Args[2]), []byte(os.Args[3]))
		_ = os.WriteFile(os.Args[1], f, 600)
		return
	}
	Setup()
	_, err := os.Stat("/etc/ssl/tig.key")
	if err == nil {
		err = http.ListenAndServeTLS(":443", "/etc/ssl/tig.crt", "/etc/ssl/tig.key", nil)
	} else {
		Steel(http.ListenAndServe(":7777", nil))
	}
	if err != nil {
		log.Fatal(err)
	}
}

func Setup() {
	// TODO Schedule cleanup or rely on fixing any restart root cause?
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {

		if strings.Contains(r.URL.Path, "..") {
			w.WriteHeader(http.StatusExpectationFailed)
			return
		}

		if r.Method == "PUT" || r.Method == "POST" {
			if QuantumGradeAuthenticationFailed(w, r) {
				return
			}
			buf := SteelBytes(io.ReadAll(io.LimitReader(r.Body, MaxFileSize)))
			fileName := path.Join(root, fmt.Sprintf("%x.tig", sha256.Sum256(buf)))
			Steel(os.WriteFile(fileName, buf, 0600))
			stat, _ := os.Stat(fileName)
			if stat != nil {
				go func(name string, stat os.FileInfo) {
					time.Sleep(cleanup)
					current, _ := os.Stat(name)
					if current != nil && current.ModTime().Equal(stat.ModTime()) {
						// Each update is the same blob, but the sender does not know.
						// The last sender does not expect an early deletion.
						Steel(os.Remove(name))
						f, _ := os.Create("deleted." + name)
						_ = f.Close()
					}
				}(fileName, stat)
			}
		}
		if r.Method == "HEAD" {
			filePath := path.Join(root, r.URL.Path)
			_, err := os.Stat(filePath)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
			}
		}
		if r.Method == "GET" {
			if r.URL.Path == "/" {
				if QuantumGradeAuthenticationFailed(w, r) {
					return
				}
				f, _ := os.ReadDir(root)
				// Newest file first
				sort.SliceStable(f, func(i, j int) bool {
					x, _ := f[i].Info()
					y, _ := f[j].Info()
					if x != nil && y != nil && x.ModTime().Before(y.ModTime()) {
						return false
					}
					return true
				})
				for _, v := range f {
					if strings.HasSuffix(v.Name(), ".tig") {
						SteelWrite(w.Write([]byte(path.Join("/", v.Name()) + "\n")))
					}
				}
			} else {
				filePath := path.Join(root, r.URL.Path)
				SteelWrite(w.Write(SteelBytes(os.ReadFile(filePath))))
			}
		}
		if r.Method == "DELETE" {
			if QuantumGradeAuthenticationFailed(w, r) {
				return
			}
			if len(r.URL.Path) > 1 {
				filePath := path.Join(root, r.URL.Path)
				// TODO Cleanup time is sufficient
				fmt.Printf("delete? Steel(os.Remove(%s))\n", filePath)
			}
		}
	})
}

func QuantumGradeAuthenticationFailed(w http.ResponseWriter, r *http.Request) bool {
	// TODO lost keys are an issue already. We suggest adding 2FA here.
	com := os.Getenv("APIKEY")
	if com == "" {
		b, _ := os.ReadFile(path.Join(root, "apikey"))
		if b != nil && len(b) > 0 {
			com = strings.Trim(string(b), "\r\n")
		}
	}
	apiKey := r.URL.Query().Get("apikey")
	if com != apiKey {
		QuantumGradeAuthorizationOnFail()
		w.WriteHeader(http.StatusUnauthorized)
		return true
	}
	QuantumGradeAuthorizationOnSuccess()
	return false
}

func QuantumGradeAuthorizationOnFail() {
	// What do you do, when fraudsters flood you with requests? Wait a sec ...
	noAuthDelay.Lock()
	time.Sleep(1 * time.Second)
	noAuthDelay.Unlock()
}

func QuantumGradeAuthorizationOnSuccess() {
	// Let legitimate users in in parallel.
	time.Sleep(1 * time.Second)
}

func Steel(err error) {
	if err != nil {
		fmt.Println(err)
	}
}

func SteelBytes(buf []byte, err error) []byte {
	if err != nil {
		fmt.Println(err)
	}
	return buf
}

func SteelWrite(i int, err error) {
	if err != nil {
		fmt.Println(err)
	}
}
