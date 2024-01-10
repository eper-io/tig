package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
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
// Any repeated patterns can be compressed at the file system level

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

// Usage
//
//echo test > /tmp/test
//echo abc > /tmp/apikey
//curl 127.0.0.1:7777/?apikey=abc
//curl -X PUT 127.0.0.1:7777/?apikey=abc -T /tmp/test
//curl -X POST 127.0.0.1:7777/?apikey=abc -T /tmp/test
//curl 127.0.0.1:7777/?apikey=abc
//curl 127.0.0.1:7777/f2ca1bb6c7e907d06dafe4687e579fce76b37e4e93b7605022da52e6ccc26fd2.tig?apikey=abc
//cat /etc/fstab | sha256sum | head -c 64
//printf "http://127.0.0.1:7777/`cat /etc/fstab | sha256sum | head -c 64`.tig"

var m sync.Mutex

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if QuantumGradeAuthenticationFailed(w, r) {
			return
		}
		if strings.Contains(r.URL.Path, "..") {
			w.WriteHeader(http.StatusExpectationFailed)
			return
		}

		if r.Method == "PUT" || r.Method == "POST" {
			buf := SteelBytes(io.ReadAll(r.Body))
			fileName := path.Join(root, fmt.Sprintf("%x.tig", sha256.Sum256(buf)))
			Steel(os.WriteFile(fileName, buf, 0700))
			go func(name string) {
				time.Sleep(cleanup)
				fmt.Printf("File with name %s is to be deleted.", name)
			}(fileName)
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
				f, _ := os.ReadDir(root)
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
			if len(r.URL.Path) > 1 {
				filePath := path.Join(root, r.URL.Path)
				Steel(os.Remove(filePath))
			}
		}
	})
	Steel(http.ListenAndServe(":7777", nil))
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
	QuantumGradeAuthorization()
	if com != apiKey {
		w.WriteHeader(http.StatusUnauthorized)
		return true
	}
	return false
}

func QuantumGradeAuthorization() {
	// TODO What do you do, when fraudsters flood you with requests? Wait a sec ...
	m.Lock()
	time.Sleep(1 * time.Second)
	m.Unlock()
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
