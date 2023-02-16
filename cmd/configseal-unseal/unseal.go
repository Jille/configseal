package main

import (
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"

	"github.com/spf13/pflag"
	"golang.org/x/crypto/nacl/secretbox"
)

var (
	url     = pflag.StringP("url", "u", "", "URL to fetch")
	keyfile = pflag.StringP("keyfile", "k", "", "Path to file containing the decryption password")
)

func main() {
	pflag.Parse()

	if *keyfile == "" || *url == "" {
		log.Fatalf("Usage: configseal-sync -k keyfile -u https://url/to/bundle [-t /path/to/extract/to] [-c reload-command]")
	}

	key, err := ioutil.ReadFile(*keyfile)
	if err != nil {
		log.Fatalf("Failed to read key from %q: %v", *keyfile, err)
	}
	if len(key) != 32 {
		log.Fatalf("Key from %q is not exactly 32 bytes", *keyfile)
	}

	// 1. Download file
	resp, err := http.Get(*url)
	if err != nil {
		log.Fatalf("Failed to fetch %s: %v", *url, err)
	}
	var nonce [24]byte
	if _, err := io.ReadFull(resp.Body, nonce[:]); err != nil {
		log.Fatalf("Failed to read nonce: %v", err)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Fatalf("Failed to read body: %v", err)
	}
	resp.Body.Close()
	// 2. Decrypt file
	bundle, ok := secretbox.Open(nil, data, &nonce, (*[32]byte)(key))
	if !ok {
		log.Fatal("Failed to decrypt bundle")
	}
	os.Stdout.Write(bundle)
}
