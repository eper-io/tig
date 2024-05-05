package main

import (
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
	"syscall"
	"time"
)

// This document is Licensed under Creative Commons CC0.
// To the extent possible under law, the author(s) have dedicated all copyright and related and neighboring rights
// to this document to the public domain worldwide.
// This document is distributed without any warranty.
// You should have received a copy of the CC0 Public Domain Dedication along with this document.
// If not, see https://creativecommons.org/publicdomain/zero/1.0/legalcode.

// tig is a low complexity git competitor.
// It is a toy git that you can review, verify, and certify cheaper.
// No branding, no-brainer.
// It just works.

// /tmp as default helps with cleanup, 10 minute is a good valve for demos, 1 gbps is an expected traffic.
var root = "/tmp"
var cleanup = 10 * time.Minute

const MaxFileSize = 128 * 1024 * 1024

var noAuthDelay sync.Mutex

func main() {
	Setup()
	_, err := os.Stat("/etc/ssl/tig.key")
	if err == nil {
		err = http.ListenAndServeTLS(":443", "/etc/ssl/tig.crt", "/etc/ssl/tig.key", nil)
	} else {
		NoIssue(http.ListenAndServe(":7777", nil))
	}
	if err != nil {
		log.Fatal(err)
	}
}

func Setup() {
	// Schedule the cleanup of any existing files
	// This covers migrations due to hardware upgrades
	// Do not rely on cleanup to cover any restart issues.
	// Crashes or hangs should be fixed instead.
	list, _ := os.ReadDir(root)
	for _, v := range list {
		if IsValidTigHash(v.Name()) {
			filePath := path.Join(root, v.Name())
			ScheduleCleanup(filePath)
		}
	}

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "..") || strings.HasPrefix(r.URL.Path, "./") {
			w.WriteHeader(http.StatusExpectationFailed)
			return
		}

		if r.Method == "PUT" || r.Method == "POST" {
			if QuantumGradeAuthenticationFailed(w, r) {
				return
			}
			WriteStore(w, r)
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
			filePath := path.Join(root, r.URL.Path)
			_, err := os.Stat(filePath)
			if err != nil {
				w.WriteHeader(http.StatusNotFound)
			}
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
	deletion := []byte(fmt.Sprintf("%s0", r.URL.Path))
	deletionPath := path.Join(root, fmt.Sprintf("%x.tig", sha256.Sum256(deletion)))
	_, err := os.Stat(deletionPath)
	if err == nil {
		w.WriteHeader(http.StatusNotFound)
		return true
	}
	filePath := path.Join(root, r.URL.Path)
	data, err := os.ReadFile(filePath)
	if err != nil {
		QuantumGradeError()
		w.WriteHeader(http.StatusExpectationFailed)
		return true
	}
	mimeType := r.URL.Query().Get("Content-Type")
	if mimeType != "" {
		w.Header().Set("Content-Type", mimeType)
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
	}
	NoIssueWrite(w.Write(data))
	chTimes := r.URL.Query().Get("chtimes")
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
			ScheduleCleanup(fileName)
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
	format := r.URL.Query().Get("format")
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
	if len(r.URL.Path) > 1 {
		filePath := path.Join(root, r.URL.Path)
		_, err := os.Stat(filePath)
		if err != nil {
			QuantumGradeError()
			w.WriteHeader(http.StatusNotFound)
			return true
		}
		// Normally you want to have a reasonable default period to verify files in your systems.
		// Privacy may be a special case, when this is needed.
		// Still, we do a day delay to prevent accidental tampering with live services.
		// The deletion marker is still a hashed file that prevents it to show up but with apikey.
		// An extra benefit of the logic is that the deletion marker is an addressed object.
		// Deleted files can be returned without quantum grade waits for attackers.
		// Coin usage checks can be very quick as a result.
		deletion := []byte(fmt.Sprintf("%s0", r.URL.Path))
		deletionPath := path.Join(root, fmt.Sprintf("%x.tig", sha256.Sum256(deletion)))
		_ = os.WriteFile(deletionPath, deletion, 0600)
		ScheduleCleanup(deletionPath)
	}
	return false
}

func WriteStore(w http.ResponseWriter, r *http.Request) {
	buf := NoIssueApi(io.ReadAll(io.LimitReader(r.Body, MaxFileSize)))
	shortName := fmt.Sprintf("%x.tig", sha256.Sum256(buf))
	if IsValidTigHash(r.URL.Path) {
		// We allow key value pairs for limited use of checkpoints, commits, and persistence tags
		shortName = fmt.Sprintf("%x.tig", sha256.Sum256([]byte(r.URL.Path)))
	} else if len(r.URL.Path) > 1 {
		return
	}
	absolutePath := path.Join(root, shortName)
	NoIssue(os.WriteFile(absolutePath, buf, 0600))
	format := r.URL.Query().Get("format")
	if format != "" {
		relativePath := path.Join("/", shortName)
		_, _ = io.WriteString(w, fmt.Sprintf(strings.Replace(format, "*", "%s", 1), relativePath))
	}
	ScheduleCleanup(absolutePath)
}

func IsValidTigHash(path string) bool {
	// We do not want to return anything else but hashed files
	return strings.HasSuffix(path, ".tig") && len(path) == len(fmt.Sprintf("/%x.tig", sha256.Sum256([]byte(""))))
}

func ScheduleCleanup(fileName string) {
	// Cleaning up files that have not been used or updated at least the default cleanup period
	stat, _ := os.Stat(fileName)
	if stat != nil {
		go func(name string, stat os.FileInfo) {
			// Ideally cleanup considers the modification time, but that may not be trusted
			marker := path.Join(path.Dir(name), stat.Name()+".deleting")
			f, _ := os.Create(marker)
			_ = f.Close()
			time.Sleep(cleanup)
			_ = syscall.Unlink(marker)
			current, _ := os.Stat(name)
			if current != nil && current.ModTime().Equal(stat.ModTime()) {
				// Each update is the same blob, but the sender does not know.
				// The last user does not expect an early deletion.
				NoIssue(os.Remove(name))
			} else {
				fmt.Println(current.ModTime(), stat.ModTime())
				ScheduleCleanup(fileName)
			}
		}(fileName, stat)
	}
}

func QuantumGradeAuthenticationFailed(w http.ResponseWriter, r *http.Request) bool {
	// Lost tokens and passwords are an issue already.
	// An api key is a good way to reliably separate apps.
	// If your browser has issues with api keys,
	// are you sure it does not have an issue with bearer tokens?
	// TODO We suggest adding 2FA here & any AI monitoring tool.
	// The on storage apikey is safer than the variable due to the mutability.
	// Make sure the logic cannot write small root files like apikey, but 64 byte SHA256.
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
	time.Sleep(12 * time.Millisecond)
	return false
}

func QuantumGradeError() {
	noAuthDelay.Lock()
	time.Sleep(12 * time.Millisecond)
	noAuthDelay.Unlock()
}

func NoIssue(err error) {
	if err != nil {
		//fmt.Println(err)
	}
}

func NoIssueApi(buf []byte, err error) []byte {
	if err != nil {
		//fmt.Println(err)
		return []byte{}
	}
	return buf
}

func NoIssueWrite(i int, err error) {
	if err != nil {
		//fmt.Println(i, err)
	}
}
