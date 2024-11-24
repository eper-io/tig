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
	"runtime"
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

var root = "/data"
var cleanup = 10 * time.Minute
const MaxFileSize = 128 * 1024 * 1024
const MaxMemSize = 4 * MaxFileSize
var cluster = "localhost"
var ddosProtection sync.Mutex
var instance = fmt.Sprintf("%d", time.Now().UnixNano()+rand.Int63())
const routedCall = "09E3F5F0-1D87-4B54-B57D-8D046D001942"
var endOfLife = time.Now().Add(time.Duration(10*365*24*time.Hour))
// MaxMemSize / MaxFileSize
var poolExternal = make(chan []byte, MaxMemSize / MaxFileSize)
// MaxMemSize / MaxFileSize to avoid deadlocks and bottlenecks
var poolCluster = make(chan []byte, MaxMemSize / MaxFileSize)
var addLocalhost = false

func main() {
	if cluster != "localhost" {
		rand.Seed(100)
		shuffleParallel := time.Duration(rand.Intn(5)) * cleanup
		endOfLife = endOfLife.Add(shuffleParallel)
	}
	_, err := os.Stat(root)
	if err != nil {
		fallback := "/tmp"
		root = fallback
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
	for i := 0; i < MaxMemSize / MaxFileSize; i++ {
		poolExternal <- make([]byte, MaxFileSize)
	}
	if cluster != "localhost" {
		for i := 0; i < MaxMemSize / MaxFileSize; i++ {
			poolCluster <- make([]byte, MaxFileSize)
		}
	}
	go func() {
		for {
			now := time.Now()
			list, _ := os.ReadDir(root)
			for _, v := range list {
				if IsValidTigHash("/"+v.Name()) {
					filePath := path.Join(root, v.Name())
					stat, _ := os.Stat(filePath)
					if stat != nil {
						if stat.ModTime().Add(cleanup).Before(now) {
							_ = os.Remove(filePath)
						}
					}
				}
				time.Sleep(cleanup / time.Duration(len(list)) / 10)
			}
			time.Sleep(cleanup)
		}
	}()
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "..") || strings.Contains(r.URL.Path, "./") {
			// This is stricter than path.Clear reducing complexity.
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		runtime.GC()
		if cluster != "localhost" && !IsCallRouted(w, r) {
			if internalCallFromCluster(w, r) {
				return
			}
		}
		buffer := <-poolExternal
		defer func(a0 []byte) {
			for i := range a0 {
				a0[i] = 0
			}
			poolExternal <- a0
		}(buffer)
		var body []byte
		if r.Body != nil {
			buf := bytes.NewBuffer(buffer)
			buf.Reset()
			n, _ := io.Copy(buf, io.LimitReader(r.Body, MaxFileSize))
			body = buffer[0:n]
			_ = r.Body.Close()
		}

		if r.Method == "PUT" || r.Method == "POST" {
			if r.URL.Path == "/kv" {
				// We allow key value pairs for limited use of persistent checkpoints, commits, and tags
				shortName := fmt.Sprintf("%x.tig", sha256.Sum256(body))
				_, _ = io.WriteString(w, "/"+shortName)
				return
			}
			if QuantumGradeAuthenticationFailed(w, r) {
				return
			}
			w.WriteHeader(http.StatusOK)
			if IsValidTigHash(r.URL.Path) {
				WriteVolatile(w, r, body)
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
				return
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

func internalCallFromCluster(w http.ResponseWriter, r *http.Request) bool {
	buffer := <-poolCluster
	defer func(a0 []byte) {
		for i := range a0 {
			a0[i] = 0
		}
		poolCluster <- a0
	}(buffer)
	var body []byte
	if r.Body != nil {
		buf := bytes.NewBuffer(buffer)
		buf.Reset()
		n, _ := io.Copy(buf, io.LimitReader(r.Body, MaxFileSize))
		body = buffer[0:n]
		_ = r.Body.Close()
	}
	bodyHash := fmt.Sprintf("%x.tig", sha256.Sum256(body))
	// UDP multicast is limited on K8S. We can use a headless service instead.
	remoteAddress := ""
	replicaAddress := "not-replicating"
	if endOfLife.Before(time.Now()) {
		replicaAddress = "replicating"
	}
	list, _ := net.LookupHost(cluster)
	if addLocalhost {
		list = append(list, "127.0.0.1")
	}
	// We use linear polling because goroutines use too much memory.
	for _, clusterAddress := range list {
		verifyAddress, rootAddress, forwardAddress := DistributedAddress(r, bodyHash, clusterAddress)
		if DistributedCheck(verifyAddress) {
			remoteAddress = forwardAddress
		}
		if replicaAddress == "replicating" {
			if DistributedCheck(rootAddress) {
				replicaAddress = remoteAddress
			}
		}
	}
	if endOfLife.Before(time.Now()) && remoteAddress == "" {
		replicaAddress = ForwardStore(w, r, replicaAddress)
		if replicaAddress != "" {
			remoteAddress = replicaAddress
		}
	}
	if remoteAddress != "" {
		DistributedCall(w, r, r.Method, body, remoteAddress)
		return true
	}
	return false
}

func ForwardStore(w http.ResponseWriter, r *http.Request, replicaAddress string) (remoteAddress string) {
	remoteAddress = ""
	if !IsValidTigHash(r.URL.Path) || replicaAddress == "" {
		w.WriteHeader(http.StatusExpectationFailed)
		return
	}
	localStore := path.Join(root, r.URL.Path)
	_, err := os.Stat(localStore)
	if err == nil {
		// Local data
		localBytes, _ := os.ReadFile(localStore)
		if localBytes != nil {
			remoteAddress = replicaAddress
			client := &http.Client{
				Transport: &http.Transport{
					TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				},
			}
			req, _ := http.NewRequest("PUT", remoteAddress, bytes.NewBuffer(localBytes))
			resp, _ := client.Do(req)
			if resp != nil && resp.Body != nil {
				_ = resp.Body.Close()
			}
		}
		_ = os.Remove(localStore)
	}
	return remoteAddress
}

func ReadStore(w http.ResponseWriter, r *http.Request) {
	mimeType := r.URL.Query().Get("Content-Type")
	if mimeType != "" {
		w.Header().Set("Content-Type", mimeType)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, post-check=0, pre-check=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
	status := ReadStoreBuffer(w, r)
	if status != http.StatusOK {
		w.WriteHeader(status)
	}
}

func ReadStoreBuffer(w io.Writer, r *http.Request) int {
	if !IsValidTigHash(r.URL.Path) {
		return http.StatusExpectationFailed
	}
	// Hashes are strong enough not to require an apikey TODO os.Link()
	filePath := path.Join(root, r.URL.Path)
	data, err := os.ReadFile(filePath)
	if err != nil {
		QuantumGradeError()
		return http.StatusNotFound
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
	return http.StatusOK
}

func MarkAsUsed(r *http.Request, fileName string) {
	chTimes := "1"
	param := r.URL.Query().Get("chtimes")
	if param != "" {
		chTimes = param
	}
	if chTimes != "0" {
		current := time.Now()
		_ = os.Chtimes(fileName, current, current)
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
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate, post-check=0, pre-check=0")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Expires", "0")
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
		_ = os.Remove(filePath)
	}
	return false
}

func WriteVolatile(w http.ResponseWriter, r *http.Request, body []byte) {
	if !IsValidTigHash(r.URL.Path) {
		return
	}
	if len(r.URL.Path) <= 1 {
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
			return
		}
	}
	format := Nvl(r.URL.Query().Get("format"), "*")
	relativePath := path.Join("/", shortName)
	_, _ = io.WriteString(w, fmt.Sprintf(strings.Replace(format, "*", "%s", 1), relativePath))
}

func WriteNonVolatile(w http.ResponseWriter, r *http.Request, body []byte) {
	if len(r.URL.Path) > 1 || r.URL.Path != "/" {
		return
	}
	shortName := fmt.Sprintf("%x.tig", sha256.Sum256(body))
	absolutePath := path.Join(root, shortName)
	flags := os.O_CREATE|os.O_TRUNC|os.O_WRONLY|os.O_EXCL
	file, err := os.OpenFile(absolutePath, flags, 0600)
	if err == nil {
		_, _ = io.Copy(file, bytes.NewBuffer(body))
		_ = file.Close()
	}
	format := Nvl(r.URL.Query().Get("format"), "*")
	relativePath := path.Join("/", shortName)
	_, _ = io.WriteString(w, fmt.Sprintf(strings.Replace(format, "*", "%s", 1), relativePath))
}

func IsCallRouted(w http.ResponseWriter, r *http.Request) bool {
	u, _ := url.Parse(r.URL.String())
	return u.Query().Get(routedCall) != ""
}

func DistributedAddress(r *http.Request, bodyHash, clusterAddress string) (string, string, string) {
	u := url.URL{Path: r.URL.Path, RawQuery: r.URL.RawQuery}
	_, err := os.Stat("/etc/ssl/tig.key")
	if err == nil {
		u.Scheme = "https"
		u.Host = clusterAddress + ":443"
	} else {
		u.Scheme = "http"
		u.Host = clusterAddress + ":7777"
	}
	q := u.Query()
	q.Add(routedCall, instance)
	u.RawQuery = q.Encode()
	forwardAddress := u.String()
	if (strings.ToUpper(r.Method) == "PUT" || strings.ToUpper(r.Method) == "POST") && (r.URL.Path == "" || r.URL.Path == "/") {
		u.Path = "/" + bodyHash
	}
	verifyAddress := u.String()
	u.Path = "/"
	rootAddress := u.String()
	return verifyAddress, rootAddress, forwardAddress
}

func DistributedCheck(address string) bool {
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
	if err != nil || resp == nil || resp.Body == nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	return true
}

func DistributedCall(w http.ResponseWriter, r *http.Request, method string, body []byte, address string) bool {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		},
	}
	req, err := http.NewRequest(method, address, bytes.NewBuffer(body))
	if err != nil {
		return false
	}
	resp, err := client.Do(req)
	if err != nil || resp == nil || resp.Body == nil {
		return false
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
	_ = resp.Body.Close()
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
		QuantumGradeError()
		w.WriteHeader(http.StatusUnauthorized)
		return true
	}
	// Let legitimate users use the system in parallel.
	QuantumGradeSuccess()
	return false
}

func QuantumGradeSuccess() {
	time.Sleep(2 * time.Millisecond)
}

func QuantumGradeError() {
	// Authentication: Plain old safe deposit box logic with pin codes covering quantum computers.
	// Authorization: What do you do, when fraudsters flood you with requests? Wait a sec ...
	// Encryption: We still rely on your OS provided TLS library .
	// This is still not optimal allowing attackers to use memory with the default http implementation.
	// Paid pro versions may use UDP.
	ddosProtection.Lock()
	time.Sleep(2 * time.Millisecond)
	ddosProtection.Unlock()
	time.Sleep(10 * time.Millisecond)
}

func NoIssueApi(buf []byte, err error) []byte {
	// No issue checking assumes an os level fix of upstream errors.
	// We do not really want to give attackers the chance to impact our logs.
	if err != nil {
		return []byte{}
	}
	return buf
}

func NoIssueWrite(i int, err error) {
	if err != nil {
	}
}

func NoIssueCopy(i int64, err error) {
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