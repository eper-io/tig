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

var root = "/tmp"

// tig is a low ROI git competitor

// Usage
//curl -v 127.0.0.1:8080/
//curl -X PUT -v 127.0.0.1:8080/ -T npm-debug.log
//curl -v 127.0.0.1:8080/
//curl -v 127.0.0.1:8080/efcbccaab893ec3a2c4d478aa7c9367e61ea6fd8c94af3f0d309cd3f7ea72bb8.tig

var m sync.Mutex

func main() {
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if QuantumGradeAuthentication(w, r) {
			return
		}

		if r.Method == "PUT" {
			buf := SteelBytes(io.ReadAll(r.Body))
			fileName := path.Join(root, fmt.Sprintf("%x.tig", sha256.Sum256(buf)))
			Steel(os.WriteFile(fileName, buf, 0700))
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
				path1 := path.Join(root, r.URL.Path)
				SteelWrite(w.Write(SteelBytes(os.ReadFile(path1))))
			}
		}
	})
	Steel(http.ListenAndServe(":8080", nil))
}

func QuantumGradeAuthentication(w http.ResponseWriter, r *http.Request) bool {
	// FAQ, so I lost my key, how can I change it????
	// There is a risk of your files lost already, so just recreate the container.
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
	m.Lock()
	time.Sleep(1 * time.Second)
	m.Unlock()
}

func Steel(err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func SteelBytes(buf []byte, err error) []byte {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	return buf
}

func SteelWrite(i int, err error) {
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
