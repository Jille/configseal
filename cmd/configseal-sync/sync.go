package main

import (
	"archive/tar"
	"bytes"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"time"

	"github.com/spf13/pflag"
	"golang.org/x/crypto/nacl/secretbox"
)

var (
	url     = pflag.StringP("url", "u", "", "URL to fetch")
	keyfile = pflag.StringP("keyfile", "k", "", "Path to file containing the decryption password")
	target  = pflag.StringP("target", "t", "", "Target to extract to")
	reload  = pflag.StringP("exec", "c", "", "Command to execute to reload")
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
	// 3. Extract tar
	tr := tar.NewReader(bytes.NewReader(bundle))
	files := map[string]string{}
	mtimes := map[string]time.Time{}
	for {
		h, err := tr.Next()
		if err != nil {
			if err == io.EOF {
				break
			}
			log.Fatalf("Failed to read tar from bundle: %v", err)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		fh, err := os.Create(filepath.Join(*target, h.Name+".tmp"))
		if err != nil {
			log.Fatalf("Failed to read %s from bundle: %v", h.Name, err)
		}
		defer os.Remove(fh.Name())
		if err := os.Chmod(fh.Name(), os.FileMode(h.Mode)); err != nil {
			log.Fatalf("Failed to chmod(%s, %o): %v", fh.Name(), h.Mode, err)
		}
		if oldfh, err := os.Open(filepath.Join(*target, h.Name)); err == nil { // err == nil
			cw := &comparingWriter{cmp: oldfh, next: fh}
			if _, err := io.Copy(cw, tr); err != nil {
				log.Fatalf("Failed to read %s from bundle: %v", h.Name, err)
			}
			cw.Finalize()
			if !cw.changed {
				if err := fh.Close(); err != nil {
					log.Fatalf("Failed to write %s: %v", fh.Name(), err)
				}
				_ = os.Remove(fh.Name())
				continue
			}
			_ = cw.cmp.(*os.File).Close()
		} else if _, err := io.Copy(fh, tr); err != nil {
			log.Fatalf("Failed to read %s from bundle: %v", h.Name, err)
		}
		_ = os.Chtimes(fh.Name(), h.ModTime, h.ModTime)
		if err := fh.Sync(); err != nil {
			log.Fatalf("Failed to write %s: %v", fh.Name(), err)
		}
		if err := fh.Close(); err != nil {
			log.Fatalf("Failed to write %s: %v", fh.Name(), err)
		}
		files[filepath.Join(*target, h.Name)] = fh.Name()
		mtimes[filepath.Join(*target, h.Name)] = h.ModTime
	}
	if len(files) == 0 {
		log.Print("No changes")
		return
	}

	// Rename files into place.
	for fn, tmp := range files {
		if err := os.Rename(tmp, fn); err != nil {
			log.Fatalf("Failed to rename %s -> %s", tmp, fn)
		}
		mtime := mtimes[fn]
		_ = os.Chtimes(fn, mtime, mtime)
	}

	// 4. Signal reload
	cmd := exec.Command("sh", "-c", *reload)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Error during reload: %v", err)
	}
}

type comparingWriter struct {
	cmp     io.Reader
	next    io.Writer
	buf     []byte
	changed bool
}

func (cw *comparingWriter) Write(p []byte) (int, error) {
	if !cw.changed {
		l := len(p)
		if cap(cw.buf) < l {
			cw.buf = make([]byte, l)
		}
		if _, err := io.ReadFull(cw.cmp, cw.buf[:l]); err != nil {
			cw.changed = true
		} else if !bytes.Equal(cw.buf[:l], p) {
			cw.changed = true
		}
	}
	return cw.next.Write(p)
}

func (cw *comparingWriter) Finalize() {
	if cap(cw.buf) < 1 {
		cw.buf = make([]byte, 1)
	}
	_, err := cw.cmp.Read(cw.buf[:1])
	if err == io.EOF {
		return
	}
	cw.changed = true
}
