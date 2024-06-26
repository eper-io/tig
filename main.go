package main

import (
	"bufio"
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

// tig is a low complexity git competitor. It is a toy git that you can review, verify, and certify cheaper.
// No branding, no-brainer. It just works mostly for distributed in memory storage like Redis or SAP Hana.

// /tmp as default helps with cleanup, 10 minute is a good valve for demos, 1 GBps is an expected traffic.
var root = "/data"
var cleanup = 10 * time.Minute
const MaxFileSize = 128 * 1024 * 1024
var dosProtection sync.Mutex

func main() {
	_, err := os.Stat(root)
	if err != nil {
		root = "/tmp"
	}
	Setup()
	_, err = os.Stat("/etc/ssl/tig.key")
	if err == nil {
		err = http.ListenAndServeTLS(":443", "/etc/ssl/tig.crt", "/etc/ssl/tig.key", nil)
	} else {
		_ = http.ListenAndServe(":7777", nil)
	}
	if err != nil {
		log.Fatal(err)
	}
}

func Setup() {
	// Schedule the cleanup of any existing files
	list, _ := os.ReadDir(root)
	for _, v := range list {
		if IsValidTigHash(v.Name()) {
			filePath := path.Join(root, v.Name())
			DelayDelete(filePath)
		}
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "..") || strings.HasPrefix(r.URL.Path, "./") {
			w.WriteHeader(http.StatusExpectationFailed)
			return
		}

		if r.Method == "PUT" || r.Method == "POST" {
			if r.URL.Path == "/kv" {
				// We allow key value pairs for limited use of checkpoints, commits, and persistence tags
				buf := NoIssueApi(io.ReadAll(io.LimitReader(r.Body, MaxFileSize)))
				shortName := fmt.Sprintf("%x.tig", sha256.Sum256(buf))
				_, _ = io.WriteString(w, "/" + shortName)
				return
			}
			if QuantumGradeAuthenticationFailed(w, r) {
				return
			}
			if IsValidTigHash(r.URL.Path) {
				WriteVolatile(w,r)
			} else {
				WriteNonVolatile(w, r)
			}
			return
		}
		if r.Method == "DELETE" {
			if !IsValidTigHash(r.URL.Path) {
				w.WriteHeader(http.StatusExpectationFailed)
				return
			}
			if QuantumGradeAuthenticationFailed(w, r) {
				return
			}
			if DeleteStore(w, r) {
				return
			}
			return
		}
		if r.Method == "HEAD" {
			if !IsValidTigHash(r.URL.Path) {
				w.WriteHeader(http.StatusExpectationFailed)
				return
			}
			_, err := os.Stat(path.Join(root, r.URL.Path))
			if err != nil {
				QuantumGradeError()
				w.WriteHeader(http.StatusNotFound)
			}
			QuantumGradeSuccess()
			return
		}
		if r.Method == "GET" {
			if r.URL.Path == "/" {
				if QuantumGradeAuthenticationFailed(w, r) {
					return
				}
				ListStore(w, r)
				return
			} else {
				if !IsValidTigHash(r.URL.Path) {
					w.WriteHeader(http.StatusExpectationFailed)
					return
				}
				if ReadStore(w, r) {
					return
				}
			}
		}
	})
}

func ReadStore(w http.ResponseWriter, r *http.Request) bool {
	// Hashes are strong enough not to require an apikey
	filePath := path.Join(root, r.URL.Path)
	// TODO os.Link()
	data, err := os.ReadFile(filePath)
	if err != nil {
		QuantumGradeError()
		w.WriteHeader(http.StatusNotFound)
		return true
	}
	mimeType := r.URL.Query().Get("Content-Type")
	if mimeType != "" {
		w.Header().Set("Content-Type", mimeType)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	if r.URL.Query().Get("burst") == "1" {
		scanner := bufio.NewScanner(bytes.NewBuffer(data))
		for scanner.Scan() {
			filePath = path.Join(root, scanner.Text())
			data, err = os.ReadFile(filePath)
			NoIssueWrite(w.Write(data))
		}
	} else {
		NoIssueWrite(w.Write(data))
	}
	chTimes := "1"
	param := r.URL.Query().Get("chtimes")
	if param != "" {
		chTimes = param
	}
	if chTimes != "0" {
		go func(buf *[]byte) {
			// allow reshuffling storage, and ensure security
			fileName := path.Join(root, fmt.Sprintf("%x.tig", sha256.Sum256(*buf)))
			//NoIssue(os.WriteFile(fileName, *buf, 0600))
			// This prevents early cleanups of frequently used blobs
			// It is equivalent to the accessed bit of x86 class processors
			// Update modification time, allow first in first out cleanups,
			// Make sure we have a simple & universal logic.
			current := time.Now()
			_ = os.Chtimes(fileName, current, current)
			DelayDelete(fileName)
		}(&data)
	}
	return false
}

func ListStore(w http.ResponseWriter, r *http.Request) {
	referenceApiKey := os.Getenv("APIKEY")
	if referenceApiKey == "" {
		apiKeyContent, _ := os.ReadFile(path.Join(root, "apikey"))
		if apiKeyContent != nil && len(apiKeyContent) > 0 {
			referenceApiKey = strings.Trim(string(apiKeyContent), "\r\n")
		}
	}
	if referenceApiKey == "" {
		// Disallow this on temporary tig stores w/o apikey
		return
	}
	// TODO Audit this on long-term stores
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
	format := Nvl(r.URL.Query().Get("format"), "*")
	for _, v := range f {
		if strings.HasSuffix(v.Name(), ".tig") {
			relativePath := path.Join("/", v.Name())
			if format != "" {
				relativePath = fmt.Sprintf(strings.Replace(format, "*", "%s", 1), relativePath)
			}
			NoIssueWrite(io.WriteString(w, relativePath+"\n"))
		}
	}
}

func DeleteStore(w http.ResponseWriter, r *http.Request) bool {
	if IsValidTigHash(r.URL.Path) {
		filePath := path.Join(root, r.URL.Path)
		data, err := os.ReadFile(filePath)
		if err != nil {
			QuantumGradeError()
			w.WriteHeader(http.StatusNotFound)
			return true
		}
		shortName := fmt.Sprintf("%x.tig", sha256.Sum256(data))
		absolutePath := path.Join(root, shortName)
		if absolutePath == filePath {
			backup := filePath + ".deleted"
			_ = os.Rename(filePath, backup)
			DelayDelete(backup)
		} else {
			_ = os.Remove(filePath)
		}
	}
	return false
}

func DelayDelete(filePath string) {
	stat, _ := os.Stat(filePath)
	if stat != nil {
		go func(original os.FileInfo, backup1 string) {
			time.Sleep(cleanup)
			stat, _ := os.Stat(backup1)
			if stat != nil {
				if original.ModTime() == stat.ModTime() {
					// This is still the same file or usage bit set.
					_ = os.Remove(filePath)
				}
			}
		}(stat, filePath)
	}
}

func WriteVolatile(w http.ResponseWriter, r *http.Request) {
	if !IsValidTigHash(r.URL.Path) {
		return
	}
	// We allow key value pairs for limited use of checkpoints, commits, and persistence tags
	shortName := r.URL.Path[1:]
	absolutePath := path.Join(root, shortName)

	// Disallow updating non-volatile "hashed" segments.
	data, _ := os.ReadFile(absolutePath)
	shortNameOnDisk := fmt.Sprintf("%x.tig", sha256.Sum256(data))
	if shortNameOnDisk == shortName {
		QuantumGradeError()
		return
	}
	setIfNot := r.URL.Query().Get("setifnot") == "1"
	flags := os.O_CREATE|os.O_TRUNC|os.O_WRONLY
	if setIfNot {
		// Key value pairs may collide. We do not use file system locks to allow pure in memory storage later
		flags = flags | os.O_EXCL
	}

	buf := NoIssueApi(io.ReadAll(io.LimitReader(r.Body, MaxFileSize)))
	file, err := os.OpenFile(absolutePath, flags, 0600)
	if err == nil {
		_, _ = io.Copy(file, bytes.NewBuffer(buf))
		_ = file.Close()
	} else {
		if setIfNot {
			// We do not use test and set (TAS) being an expensive algorithm.
			// The likes of XCHG are also expensive.
			// Setting if not set is good enough for synchronization w/ retry.
			return
		}
	}
	format := Nvl(r.URL.Query().Get("format"), "*")
	relativePath := path.Join("/", shortName)
	_, _ = io.WriteString(w, fmt.Sprintf(strings.Replace(format, "*", "%s", 1), relativePath))
	DelayDelete(absolutePath)
}

func WriteNonVolatile(w http.ResponseWriter, r *http.Request) {
	buf := NoIssueApi(io.ReadAll(io.LimitReader(r.Body, MaxFileSize)))
	shortName := fmt.Sprintf("%x.tig", sha256.Sum256(buf))
	absolutePath := path.Join(root, shortName)
	if len(r.URL.Path) > 1 || r.URL.Path != "/" {
		return
	}
	flags := os.O_CREATE|os.O_TRUNC|os.O_WRONLY | os.O_EXCL
	file, err := os.OpenFile(absolutePath, flags, 0600)
	if err == nil {
		_, _ = io.Copy(file, bytes.NewBuffer(buf))
		_ = file.Close()
	}
	format := Nvl(r.URL.Query().Get("format"), "*")
	relativePath := path.Join("/", shortName)
	_, _ = io.WriteString(w, fmt.Sprintf(strings.Replace(format, "*", "%s", 1), relativePath))
	DelayDelete(absolutePath)
}

func IsValidTigHash(path string) bool {
	// We do not want to return anything else but hashed files
	return strings.HasSuffix(path, ".tig") && len(path) == len(fmt.Sprintf("/%x.tig", sha256.Sum256([]byte(""))))
}

func QuantumGradeAuthenticationFailed(w http.ResponseWriter, r *http.Request) bool {
	// TODO Make this on demand
	referenceApiKey := os.Getenv("APIKEY")
	if referenceApiKey == "" {
		apiKeyContent, _ := os.ReadFile(path.Join(root, "apikey"))
		if apiKeyContent != nil && len(apiKeyContent) > 0 {
			referenceApiKey = strings.Trim(string(apiKeyContent), "\r\n")
		}
	}
	apiKey := r.URL.Query().Get("apikey")
	if referenceApiKey != apiKey {
		// Authentication: Plain old safe deposit box logic with pin codes covering quantum computers.
		// Authorization: What do you do, when fraudsters flood you with requests? Wait a sec ...
		// Encryption: We still rely on your OS provided TLS library .
		QuantumGradeError()
		w.WriteHeader(http.StatusUnauthorized)
		return true
	}
	// Let legitimate users use the system in parallel.
	QuantumGradeSuccess()
	return false
}

func QuantumGradeSuccess() {
	time.Sleep(12 * time.Millisecond)
}

func QuantumGradeError() {
	dosProtection.Lock()
	time.Sleep(20 * time.Millisecond)
	dosProtection.Unlock()
}

func NoIssueApi(buf []byte, err error) []byte {
	if err != nil {
		return []byte{}
	}
	return buf
}

func NoIssueWrite(i int, err error) {
	if err != nil {
	}
}

func Nvl(in string, nvl string) (s string){
	s = in
	if s == "" {
		s = nvl
	}
	return
}