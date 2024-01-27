package main

import (
	"bytes"
	"os"
)

func main() {
	f, _ := os.ReadFile(os.Args[1])
	f = bytes.ReplaceAll(f, []byte(os.Args[2]), []byte(os.Args[3]))
	_ = os.WriteFile(os.Args[1], f, 600)
}
