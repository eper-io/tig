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

// tig is a low ROI git competitor.
// The main design decision is to let the client deal with ordering and tagging.

// This document is Licensed under Creative Commons CC0.
// To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring rights
// to this document to the public domain worldwide.
// This document is distributed without any warranty.
// You should have received a copy of the CC0 Public Domain Dedication along with this document.
// If not, see https://creativecommons.org/publicdomain/zero/1.0/legalcode.

// Storage directory. Suggestions:
// /tmp It cleans up fast, it is quick memory based storage sometimes.
// /usr/lib It is a good choice for executable modules. It is persistent.
// /var/log Choose this for persistent data. It is persistent.
// /opt/ Use this for entire solutions. It is persistent.
// ~/ Use, if you run outside a container without privileges, but you need persistence across reboot.
// It is a good idea to delayed delete files setting `cleanup`.
// Clients can recreate them making the system more resilient and compliant with privacy regulations.

var root = "/tmp"
var cleanup = 10 * time.Minute

// Usage
//curl 127.0.0.1:7777/
//curl -X PUT 127.0.0.1:7777/ -T /etc/fstab
//curl -X POST 127.0.0.1:7777/ -T /etc/fstab
//curl 127.0.0.1:7777/
//curl 127.0.0.1:7777/efcbccaab893ec3a2c4d478aa7c9367e61ea6fd8c94af3f0d309cd3f7ea72bb8.tig
//cat /etc/fstab | sha256sum | head -c 64
//printf "http://127.0.0.1:7777/`cat /etc/fstab | sha256sum | head -c 64`.tig"

var m sync.Mutex

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if QuantumGradeAuthenticationFailed(w, r) {
			return
		}

		if r.Method == "PUT" || r.Method == "POST" {
			buf := SteelBytes(io.ReadAll(r.Body))
			fileName := path.Join(root, fmt.Sprintf("%x.tig", sha256.Sum256(buf)))
			Steel(os.WriteFile(fileName, buf, 0700))
			go func(name string) {
				time.Sleep(10 * time.Minute)
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
	})
	Steel(http.ListenAndServe(":7777", nil))
}

func QuantumGradeAuthenticationFailed(w http.ResponseWriter, r *http.Request) bool {
	// TODO lost keys are an issue already. We suggest adding 2FA here.
	com := os.Getenv("APIKEY")
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
