package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"net/http"
	"net/url"
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

// tig is a low complexity data and code storage solution. It is a toy git that you can review, verify, and certify cheaper.
// No branding, no-brainer. It just works mostly for distributed in memory storage like Redis or SAP Hana.

//10 minute is a good valve for demos, 1 GBps is a common cloud bandwidth.
var root = "/data"
var cleanup = 10 * time.Minute
const MaxFileSize = 128 * 1024 * 1024
var cluster = "localhost"
var ddosProtection sync.Mutex
var instance = fmt.Sprintf("%d", time.Now().UnixNano()+rand.Int63())

func main() {
	_, err := os.Stat(root)
	if err != nil {
		// /tmp as fallback helps with cleanup
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
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if cluster != "localhost" && IsDistributedLocalCall(w, r) {
			w.WriteHeader(http.StatusExpectationFailed)
			return
		}
		body := NoIssueApi(io.ReadAll(io.LimitReader(r.Body, MaxFileSize)))
		if cluster != "localhost" && !IsDistributedCall(w, r) {
			// UDP multicast is limited on K8S. We can use a headless service instead.
			loc := ""
			var wg sync.WaitGroup
			list, _ := net.LookupHost(cluster)
			for _, v := range list {
				wg.Add(1)
				go func(_w http.ResponseWriter, _r *http.Request, address string) {
					fullAddress, forwardAddress := DistributedAddress(_w, _r, body, address)
					if DistributedCheck(_w, _r, fullAddress) {
						loc = forwardAddress
					}
					wg.Done()
				}(w, r, v)
			}
			wg.Wait()
			if loc != "" {
				DistributedCall(w, r, body, loc)
				return
			}
		}

		if r.Method == "PUT" || r.Method == "POST" {
			if r.URL.Path == "/kv" {
				// We allow key value pairs for limited use of persistent checkpoints, commits, and tags
				shortName := fmt.Sprintf("%x.tig", sha256.Sum256(body))
				_, _ = io.WriteString(w, "/" + shortName)
				return
			}
			if QuantumGradeAuthenticationFailed(w, r) {
				return
			}
			if IsValidTigHash(r.URL.Path) {
				WriteVolatile(w,r, body)
			} else {
				WriteNonVolatile(w, r, body)
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
			w.WriteHeader(http.StatusOK)
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
				ReadStore(w, r)
			}
		}
	})
}

func ReadStore(w http.ResponseWriter, r *http.Request) {
	if !IsValidTigHash(r.URL.Path) {
		w.WriteHeader(http.StatusExpectationFailed)
		return
	}
	// Hashes are strong enough not to require an apikey TODO os.Link()
	filePath := path.Join(root, r.URL.Path)
	data, err := os.ReadFile(filePath)
	if err != nil {
		QuantumGradeError()
		w.WriteHeader(http.StatusNotFound)
		return
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
			MarkAsUsed(r, filePath)
			NoIssueWrite(w.Write(data))
		}
	} else {
		NoIssueWrite(w.Write(data))
		MarkAsUsed(r, filePath)
	}
}

func MarkAsUsed(r *http.Request, fileName string) {
	chTimes := "1"
	param := r.URL.Query().Get("chtimes")
	if param != "" {
		chTimes = param
	}
	if chTimes != "0" {
		go func(fileName1 string) {
			current := time.Now()
			_ = os.Chtimes(fileName, current, current)
			DelayDelete(fileName1)
		}(fileName)
	}

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

func WriteVolatile(w http.ResponseWriter, r *http.Request, body []byte) {
	if !IsValidTigHash(r.URL.Path) {
		return
	}
	// We allow key value pairs for limited use of checkpoints, commits, and persistence tags
	shortName := r.URL.Path[1:]
	absolutePath := path.Join(root, shortName)

	data, _ := os.ReadFile(absolutePath)
	shortNameOnDisk := fmt.Sprintf("%x.tig", sha256.Sum256(data))
	if shortNameOnDisk == shortName {
		// Disallow updating secure hashed segments already stored.
		QuantumGradeError()
		return
	}
	setIfNot := r.URL.Query().Get("setifnot") == "1"
	flags := os.O_CREATE|os.O_WRONLY
	if setIfNot {
		// Key value pairs may collide. We do not use file system locks to allow pure in memory storage later
		flags = flags | os.O_EXCL
	}
	appendIndex := r.URL.Query().Get("append") == "1"
	if appendIndex {
		flags = flags | os.O_APPEND
	} else {
		flags = flags | os.O_TRUNC
	}
	file, err := os.OpenFile(absolutePath, flags, 0600)
	if err == nil {
		_, _ = io.Copy(file, bytes.NewBuffer(body))
		_ = file.Close()
	} else {
		if setIfNot {
			// We do not use test and set (TAS) considered expensive such as (XCHG).
			// Setting if not set is good enough for synchronization w/ retry.
			return
		}
	}
	format := Nvl(r.URL.Query().Get("format"), "*")
	relativePath := path.Join("/", shortName)
	_, _ = io.WriteString(w, fmt.Sprintf(strings.Replace(format, "*", "%s", 1), relativePath))
	DelayDelete(absolutePath)
}

func WriteNonVolatile(w http.ResponseWriter, r *http.Request, body []byte) {
	shortName := fmt.Sprintf("%x.tig", sha256.Sum256(body))
	absolutePath := path.Join(root, shortName)
	if len(r.URL.Path) > 1 || r.URL.Path != "/" {
		return
	}
	flags := os.O_CREATE|os.O_TRUNC|os.O_WRONLY|os.O_EXCL
	file, err := os.OpenFile(absolutePath, flags, 0600)
	if err == nil {
		_, _ = io.Copy(file, bytes.NewBuffer(body))
		_ = file.Close()
	}
	format := Nvl(r.URL.Query().Get("format"), "*")
	relativePath := path.Join("/", shortName)
	_, _ = io.WriteString(w, fmt.Sprintf(strings.Replace(format, "*", "%s", 1), relativePath))
	DelayDelete(absolutePath)
}

func IsDistributedLocalCall(w http.ResponseWriter, r *http.Request) bool {
	u, _ := url.Parse(r.URL.String())
	if strings.ToUpper(r.Method) == "HEAD" && u.Query().Get("09E3F5F0-1D87-4B54-B57D-8D046D001942") == instance {
		return true
	}
	return false
}

func IsDistributedCall(w http.ResponseWriter, r *http.Request) bool {
	u, _ := url.Parse(r.URL.String())
	// TODO Forward all calls at teardown time
	if u.Query().Get("09E3F5F0-1D87-4B54-B57D-8D046D001942") != "" {
		return true
	}
	return false
}

func DistributedAddress(w http.ResponseWriter, r *http.Request, body []byte, address string) (string, string) {
	u, _ := url.Parse(r.URL.String())
	_, err := os.Stat("/etc/ssl/tig.key")
	if err == nil {
		u.Scheme = "https"
		u.Host = address + ":443"
	} else {
		u.Scheme = "http"
		u.Host = address + ":7777"
	}
	q := u.Query()
	q.Add("09E3F5F0-1D87-4B54-B57D-8D046D001942", instance)
	u.RawQuery = q.Encode()
	forwardAddress := u.String()
	if (strings.ToUpper(r.Method) == "PUT" || strings.ToUpper(r.Method) == "POST") && (u.RawPath == "" || u.RawPath == "/") {
		shortName := fmt.Sprintf("%x.tig", sha256.Sum256(body))
		u.Path = "/" + shortName
	}
	return u.String(), forwardAddress
}

func DistributedCheck(w http.ResponseWriter, r *http.Request, address string) bool {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	req, err := http.NewRequest("HEAD", address, nil)
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	if resp.Body != nil {
		_ = resp.Body.Close()
	}
	if resp.StatusCode != http.StatusOK {
		return false
	}
	return true
}

func DistributedCall(w http.ResponseWriter, r *http.Request, body []byte, address string) bool {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	req, err := http.NewRequest(strings.ToUpper(r.Method), address, bytes.NewBuffer(body))
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	w.WriteHeader(resp.StatusCode)
	if resp.Body != nil {
		_, _ = io.Copy(w, resp.Body)
		_ = resp.Body.Close()
	}
	return true
}

func IsValidTigHash(path string) bool {
	// We do not want to return anything else but hashed files
	return strings.HasSuffix(path, ".tig") && len(path) == len(fmt.Sprintf("/%x.tig", sha256.Sum256([]byte(""))))
}

func QuantumGradeAuthenticationFailed(w http.ResponseWriter, r *http.Request) bool {
	referenceApiKey := os.Getenv("APIKEY")
	if referenceApiKey == "" {
		// TODO This can use a kv pair
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
	time.Sleep(6 * time.Millisecond)
}

func QuantumGradeError() {
	ddosProtection.Lock()
	time.Sleep(10 * time.Millisecond)
	ddosProtection.Unlock()
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