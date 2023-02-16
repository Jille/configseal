// Binary keygen generates a new 32 byte random key.
package main

import (
	"crypto/rand"
	"log"
	"os"

	"github.com/spf13/pflag"
)

var ()

func main() {
	pflag.Parse()

	if pflag.NArg() != 1 {
		log.Fatalf("Usage: configseal-keygen <keyfile>")
	}

	fn := pflag.Arg(0)

	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		log.Fatalf("Failed to generate random key: %v", err)
	}

	fh, err := os.Create(fn)
	if err != nil {
		log.Fatalf("open(%q): %v", fh, err)
	}
	if err := os.Chmod(fh.Name(), 0600); err != nil {
		log.Fatalf("chmod(%q, 0600): %v", fh, err)
	}
	if _, err := fh.Write(key[:]); err != nil {
		log.Fatalf("write(%q): %v", fh, err)
	}
	if err := fh.Sync(); err != nil {
		log.Fatalf("fsync(%q): %v", fh, err)
	}
	if err := fh.Close(); err != nil {
		log.Fatalf("close(%q): %v", fh, err)
	}
}
