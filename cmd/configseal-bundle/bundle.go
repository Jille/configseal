package main

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"

	"github.com/spf13/pflag"
	"golang.org/x/crypto/nacl/secretbox"
)

var (
	keyfile = pflag.StringP("keyfile", "k", "", "Path to file containing the decryption password")
	outfile = pflag.StringP("outfile", "o", "", "Path to output bundle file")
)

func main() {
	pflag.Parse()

	if pflag.NArg() == 0 {
		log.Fatal("Usage: configseal-bundle -k keyfile -o bundle.out myfile1 myfile2 ...")
	}

	cmd := exec.Command("tar", append([]string{"cLf", "-"}, pflag.Args()...)...)
	cmd.Stderr = os.Stderr
	data, err := cmd.Output()
	if err != nil {
		log.Fatalf("Failed to archive files into a tar: %v", err)
	}

	if err := Seal(*keyfile, *outfile, data); err != nil {
		log.Fatal(err)
	}
}

func Seal(keyfile, outfile string, data []byte) error {
	key, err := ioutil.ReadFile(keyfile)
	if err != nil {
		return fmt.Errorf("failed to read key from %q: %v", keyfile, err)
	}
	if len(key) != 32 {
		return fmt.Errorf("key from %q is not exactly 32 bytes", keyfile)
	}

	var nonce [24]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return fmt.Errorf("failed to generate random nonce: %w", err)
	}
	sealed := secretbox.Seal(nil, data, &nonce, (*[32]byte)(key))

	fh, err := os.Create(outfile + ".tmp")
	if err != nil {
		return fmt.Errorf("create(%q): %w", outfile+".tmp", err)
	}
	if _, err := fh.Write(nonce[:]); err != nil {
		return fmt.Errorf("write(%q): %w", outfile+".tmp", err)
	}
	if _, err := fh.Write(sealed); err != nil {
		return fmt.Errorf("write(%q): %w", outfile+".tmp", err)
	}
	if err := fh.Close(); err != nil {
		return fmt.Errorf("close(%q): %w", outfile+".tmp", err)
	}
	if err := os.Rename(outfile+".tmp", outfile); err != nil {
		return fmt.Errorf("rename(%q, %q): %w", outfile+".tmp", outfile, err)
	}
	return nil
}
