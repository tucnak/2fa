// Copyright 2017 The Go Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// 2fa is a two-factor authentication agent.
//
// Usage:
//
//	2fa -add [-7] [-8] [-hotp] name
//	2fa -list
//	2fa [-clip] name
//
// “2fa -add name” adds a new key to the 2fa keychain with the given name.
// It prints a prompt to standard error and reads a two-factor key from standard input.
// Two-factor keys are short case-insensitive strings of letters A-Z and digits 2-7.
//
// By default the new key generates time-based (TOTP) authentication codes;
// the -hotp flag makes the new key generate counter-based (HOTP) codes instead.
//
// By default the new key generates 6-digit codes; the -7 and -8 flags select
// 7- and 8-digit codes instead.
//
// “2fa -list” lists the names of all the keys in the keychain.
//
// “2fa name” prints a two-factor authentication code from the key with the
// given name. If “-clip” is specified, 2fa also copies the code to the system
// clipboard.
//
// With no arguments, 2fa prints two-factor authentication codes from all
// known time-based keys.
//
// The default time-based authentication codes are derived from a hash of
// the key and the current time, so it is important that the system clock have
// at least one-minute accuracy.
//
// The keychain is stored unencrypted in the text file $HOME/.2fa.
//
// Example
//
// During GitHub 2FA setup, at the “Scan this barcode with your app” step,
// click the “enter this text code instead” link. A window pops up showing
// “your two-factor secret,” a short string of letters and digits.
//
// Add it to 2fa under the name github, typing the secret at the prompt:
//
//	$ 2fa -add github
//	2fa key for github: nzxxiidbebvwk6jb
//	$
//
// Then whenever GitHub prompts for a 2FA code, run 2fa to obtain one:
//
//	$ 2fa github
//	268346
//	$
//
// Or to type less:
//
//	$ 2fa
//	268346	github
//	$
//
package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"flag"
	"fmt"
	"github.com/keybase/go-keychain"
	"io/ioutil"
	"log"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/atotto/clipboard"
)

var (
	flagAdd    = flag.Bool("add", false, "[-7] [-8] [-hotp] keyname")
	flagList   = flag.Bool("list", false, "list keys")
	flagHotp   = flag.Bool("hotp", false, "add key as HOTP (counter-based) key")
	flag7      = flag.Bool("7", false, "generate 7-digit code")
	flag8      = flag.Bool("8", false, "generate 8-digit code")
	flagClip   = flag.Bool("clip", false, "copy code to the clipboard")
	flagImport = flag.Bool("import", false, "import from stdin")
)

func usage() {
	flag.Usage()
	os.Exit(2)
}

func main() {
	log.SetPrefix("2fa: ")
	log.SetFlags(0)
	flag.Parse()

	k := readKeychain()

	if *flagImport {
		b, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			log.Fatal(err)
		}
		if err := k.importBytes(b); err != nil {
			log.Fatal(err)
		}
	}
	if *flagList {
		if flag.NArg() != 0 {
			usage()
		}
		k.list()
		return
	}
	if flag.NArg() == 0 && !*flagAdd {
		if *flagClip {
			usage()
		}
		k.showAll()
		return
	}
	if flag.NArg() != 1 {
		usage()
	}
	name := flag.Arg(0)
	if strings.IndexFunc(name, unicode.IsSpace) >= 0 {
		log.Fatal("name must not contain spaces")
	}
	if *flagAdd {
		if *flagClip {
			usage()
		}
		k.add(name)
		return
	}
	k.show(name)
}

type Keychain struct {
	file string
	data []byte
	keys map[string]Key
}

type Key struct {
	raw    []byte
	digits int
	offset int // offset of counter
}

const counterLen = 20

func readKeychain() *Keychain {
	k := &Keychain{
		keys: make(map[string]Key),
	}

	switch keyfile := os.Getenv("KEYS_2FA"); keyfile {
	case "":
		b, err := queryKeychain()
		if err == nil {
			k.data = b
			break
		}

		log.Println("system keychain:", err)
		// to make sure $HOME is set
		userAccount()
		keyfile = os.Getenv("HOME") + "/.2fa"
		fallthrough
	default:
		b, err := ioutil.ReadFile(keyfile)
		if err != nil {
			if os.IsNotExist(err) {
				f, err := os.OpenFile(keyfile, os.O_CREATE, 0600)
				if err != nil {
					log.Fatalf("could not create %s: %v", keyfile, err)
				}
				if err := f.Close(); err != nil {
					log.Fatalf("could not close newly created %s: %v", keyfile, err)
				}
				return k
			}
			log.Fatalf("could not open %s: %v", keyfile, err)
		}
		fmt.Fprintf(os.Stderr, "%s\n\n", keyfile)
		k.file = keyfile
		k.data = b
	}

	lines := bytes.SplitAfter(k.data, []byte("\n"))
	offset := 0
	for i, line := range lines {
		lineno := i + 1
		offset += len(line)
		f := bytes.Split(bytes.TrimSuffix(line, []byte("\n")), []byte(" "))
		if len(f) == 1 && len(f[0]) == 0 {
			continue
		}
		if len(f) >= 3 && len(f[1]) == 1 && '6' <= f[1][0] && f[1][0] <= '8' {
			var k0 Key
			name := string(f[0])
			k0.digits = int(f[1][0] - '0')
			raw, err := decodeKey(string(f[2]))
			if err == nil {
				k0.raw = raw
				if len(f) == 3 {
					k.keys[name] = k0
					continue
				}
				if len(f) == 4 && len(f[3]) == counterLen {
					_, err := strconv.ParseUint(string(f[3]), 10, 64)
					if err == nil {
						// Valid counter.
						k0.offset = offset - counterLen
						if line[len(line)-1] == '\n' {
							k0.offset--
						}
						k.keys[name] = k0
						continue
					}
				}
			}
		}
		log.Printf("%s:%d: malformed key", k.file, lineno)
	}
	return k
}

func (k *Keychain) importBytes(b []byte) error {
	item := keychainItem()
	item.SetData(b)
	return keychain.UpdateItem(item, item)
}

func (k *Keychain) list() {
	var names []string
	for name := range k.keys {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		fmt.Println(name)
	}
}

func noSpace(r rune) rune {
	if unicode.IsSpace(r) {
		return -1
	}
	return r
}

func (k *Keychain) add(name string) {
	size := 6
	if *flag7 {
		size = 7
		if *flag8 {
			log.Fatalf("cannot use -7 and -8 together")
		}
	} else if *flag8 {
		size = 8
	}

	fmt.Fprintf(os.Stderr, "2fa key for %s: ", name)
	text, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		log.Fatalf("error reading key: %v", err)
	}
	text = strings.Map(noSpace, text)
	text += strings.Repeat("=", -len(text)&7) // pad to 8 bytes
	if _, err := decodeKey(text); err != nil {
		log.Fatalf("invalid key: %v", err)
	}

	line := fmt.Sprintf("%s %d %s", name, size, text)
	if *flagHotp {
		line += " " + strings.Repeat("0", 20)
	}
	line += "\n"
	k.data = append(k.data, []byte(line)...)
	if err := k.commit(); err != nil {
		log.Fatal(err)
	}
}

func (k *Keychain) commit() error {
	switch k.file {
	case "":
		item := keychainItem()
		item.SetData(k.data)
		if err := keychain.UpdateItem(item, item); err != nil {
			return fmt.Errorf("keychain item update: %w", err)
		}
	default:
		f, err := os.OpenFile(k.file, os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0600)
		if err != nil {
			return fmt.Errorf("opening keychain file %s: %w", k.file, err)
		}
		if _, err := f.Write(k.data); err != nil {
			return fmt.Errorf("adding key: %w", err)
		}
		if err := f.Close(); err != nil {
			return fmt.Errorf("adding key: %w", err)
		}
	}
	return nil
}

func (k *Keychain) code(name string) string {
	k0, ok := k.keys[name]
	if !ok {
		log.Fatalf("no such key %q", name)
	}
	var code int
	if off := k0.offset; off != 0 {
		n, err := strconv.ParseUint(string(k.data[off:off+counterLen]), 10, 64)
		if err != nil {
			log.Fatalf("malformed key counter for %q (%q)", name, k.data[off:off+counterLen])
		}
		n++
		ctr := []byte(fmt.Sprintf("%0*d", counterLen, n))
		k.data = append(k.data[:off], append(ctr, k.data[off+counterLen:]...)...)
		if err := k.commit(); err != nil {
			log.Fatal(err)
		}
		code = hotp(k0.raw, n, k0.digits)
	} else {
		// Time-based key.
		code = totp(k0.raw, time.Now(), k0.digits)
	}
	return fmt.Sprintf("%0*d", k0.digits, code)
}

func (k *Keychain) show(name string) {
	code := k.code(name)
	if *flagClip {
		if err := clipboard.WriteAll(code); err != nil {
			log.Fatal(err)
		}
	}
	fmt.Printf("%s\n", code)
}

func (k *Keychain) showAll() {
	var names []string
	max := 0
	for name, k := range k.keys {
		names = append(names, name)
		if max < k.digits {
			max = k.digits
		}
	}
	sort.Strings(names)
	for _, name := range names {
		k0 := k.keys[name]
		code := strings.Repeat("-", k0.digits)
		if k0.offset == 0 {
			code = k.code(name)
		}
		fmt.Printf("%-*s\t%s\n", max, code, name)
	}
}

func decodeKey(key string) ([]byte, error) {
	return base32.StdEncoding.DecodeString(strings.ToUpper(key))
}

func hotp(key []byte, counter uint64, digits int) int {
	h := hmac.New(sha1.New, key)
	binary.Write(h, binary.BigEndian, counter)
	sum := h.Sum(nil)
	v := binary.BigEndian.Uint32(sum[sum[len(sum)-1]&0x0F:]) & 0x7FFFFFFF
	d := uint32(1)
	for i := 0; i < digits && i < 8; i++ {
		d *= 10
	}
	return int(v % d)
}

func totp(key []byte, t time.Time, digits int) int {
	return hotp(key, uint64(t.UnixNano())/30e9, digits)
}
