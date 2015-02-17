package main

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"reflect"
	"regexp"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/codegangsta/cli"
	"github.com/mitchellh/go-homedir"

	// Autoload
	_ "github.com/joho/godotenv/autoload"
)

// GenericFlag is the flag type for types implementing Generic
type SigEntry struct {
	SigBytes []byte
}

type KeyDiscoveryRevealEntry struct {
	PubKeyBytes []byte
}

type KeyEntry struct {
	Cmd                     string
	Identifier              string
	DoubleSha256PubKeyBytes []byte
	DiscoveryEntry          KeyDiscoveryRevealEntry
}

func readLines(path string) ([]string, error) {
	path, err := homedir.Expand(path)
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines, scanner.Err()
}

func createKeyfile(path string) error {
	path, err := homedir.Expand(path)
	if err != nil {
		return err
	}

	lines, err := readLines(path)
	if len(lines) > 0 {
		return errors.New("Won't overwrite file")
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	k, err := btcec.NewPrivateKey(btcec.S256())

	w := bufio.NewWriter(file)
	fmt.Fprintln(w, hex.EncodeToString(k.Serialize()))

	return w.Flush()
}

func cp(dst, src string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}
	// no need to check errors on read only file, we already got everything
	// we need from the filesystem, so nothing can go wrong now.
	defer s.Close()
	d, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(d, s); err != nil {
		d.Close()
		return err
	}
	return d.Close()
}

func createTrustfile(path string) error {
	path, err := homedir.Expand(path)
	if err != nil {
		return err
	}

	lines, err := readLines(path)
	if len(lines) > 0 {
		return errors.New("Trustfile already exists at specified path")
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	return nil
}

func verifyNoDoubleAdd(keys []KeyEntry) error {
	logKeys := map[string]int{}

	if len(keys) == 1 {
		if keys[0].Cmd == "+" {
			return nil
		} else {
			return errors.New("An entry must be added before it may be removed")
		}
	}

	for _, key := range keys {
		p, err := btcec.ParsePubKey(key.DiscoveryEntry.PubKeyBytes, btcec.S256())
		if err != nil {
			return err
		}
		c := hex.EncodeToString(p.SerializeCompressed())
		_, hasKey := logKeys[c]
		if hasKey {
			if key.Cmd == "+" {
				return errors.New("An entry must be removed before it may be added again")
			}
		} else {
			if key.Cmd == "-" {
				return errors.New("An entry must be added before it may be removed")
			}
		}
		if key.Cmd == "-" {
			delete(logKeys, c)
		} else if key.Cmd == "+" {
			logKeys[c] = 1
		}
	}

	return nil
}

func contentForEntryIndex(index int, keys []KeyEntry, sigs [][]SigEntry) (content string, err error) {
	if index == 0 {
		return
	}
	if len(keys)-1 < index {
		return "", errors.New("Index out of bounds")
	}

	content = ""
	for i, entry := range keys {
		// Make sure the content is the same
		pk, _ := btcec.ParsePubKey(entry.DiscoveryEntry.PubKeyBytes, btcec.S256())
		compHex := hex.EncodeToString(pk.SerializeCompressed())
		if i > 0 {
			content += "\n"
		}
		if entry.Cmd == "+" {
			content += strings.Join([]string{"=", entry.Cmd, " ", entry.Identifier, " ", compHex}, "")
		} else if entry.Cmd == "-" {
			content += strings.Join([]string{"=", entry.Cmd, " ", compHex}, "")
		}

		// Don't include the sigs in the last entry
		// Since that is what we're looking to sign
		if i == index {
			return content, nil
		}

		sigContent := ""
		for j, sig := range sigs[i] {
			if j > 0 {
				sigContent += "\n"
			}
			if p, err := checkSigAndRecoverCompact(sig, sigContent); err == nil {
				sigContent += strings.Join([]string{"SigFrom", " ", hex.EncodeToString(p.SerializeCompressed()), " ", hex.EncodeToString(sig.SigBytes)}, "")
			} else {

			}
		}
		content += sigContent
	}

	return content, nil
}

func signersForEntryIndex(index int, keys []KeyEntry, sigs [][]SigEntry) (signers map[string]*btcec.PublicKey, required int, err error) {
	if len(keys) == 0 {
		return
	}

	if index > len(keys)-1 {
		return map[string]*btcec.PublicKey{}, -1, errors.New("Index out of bounds")
	}

	// Special case for first bootstrap sig
	if index == 0 && len(keys) == 1 && len(sigs[0]) == 0 {
		return map[string]*btcec.PublicKey{}, 1, nil
	}

	required = -1
	for i, entry := range keys {
		// Make sure the content is the same
		pk, _ := btcec.ParsePubKey(entry.DiscoveryEntry.PubKeyBytes, btcec.S256())

		required = 2
		if len(signers) < 2 {
			required = len(signers)
		}

		// If we are at the specified index, break
		// out of the loop, since we only want the signers
		// that can approve this entry, NOT including the possibly-approved
		// key entry.
		if index == i {
			break
		}

		content, err := contentForEntryIndex(i, keys, sigs)
		if err != nil {
			return map[string]*btcec.PublicKey{}, -1, err
		}

		numSuccessfulSigs := 0
		for _, sig := range sigs[i] {
			if checkSig(sig, content, signers) {
				numSuccessfulSigs += 1
				if numSuccessfulSigs >= required {
					k := hex.EncodeToString(pk.SerializeCompressed())
					if entry.Cmd == "+" {
						signers[k] = pk
					} else if entry.Cmd == "-" {
						delete(signers, k)
					}
				}
			}
		}
	}

	return signers, required, nil
}

func checkSigAndRecoverCompact(sig SigEntry, content string) (*btcec.PublicKey, error) {
	hasher := sha256.New()
	hasher.Write([]byte(content))
	contentSha := hasher.Sum(nil)

	if k, _, err := btcec.RecoverCompact(btcec.S256(), sig.SigBytes, contentSha); err == nil {
		return k, nil
	} else {
		return nil, err
	}
}

func checkSig(sig SigEntry, content string, signers map[string]*btcec.PublicKey) bool {
	if _, err := checkSigAndRecoverCompact(sig, content); err == nil {
		return true
	} else {
		return false
	}
}

func verifySequentialEntrySigsAtIndex(index int, keys []KeyEntry, sigs [][]SigEntry) error {
	for i, _ := range keys {
		// Get the content to sign
		content, err := contentForEntryIndex(i, keys, sigs)
		if err != nil {
			return err
		}

		signers, req, err := signersForEntryIndex(i, keys, sigs)
		if err != nil {
			return err
		}

		successfulSigs := 0
		for _, sig := range sigs[i] {
			if p, err := checkSigAndRecoverCompact(sig, content); err == nil {
				if _, ok := signers[hex.EncodeToString(p.SerializeCompressed())]; ok {
					// Signers can only sign once. Remove after successful sig
					delete(signers, hex.EncodeToString(p.SerializeCompressed()))
					successfulSigs += 1
				}
			}
		}

		if successfulSigs < req {
			return errors.New("Signature threshold not passed")
		}

		if i == index {
			break
		}
	}

	return nil
}

func verifyDbFile(path string, skipLast bool) error {
	keys, sigs, err := parseDbFile(path)
	if err != nil {
		return err
	}

	if err := verifyNoDoubleAdd(keys); err != nil {
		return err
	}

	if len(keys) > 0 {
		if err := verifySequentialEntrySigsAtIndex(len(keys)-1, keys, sigs); err != nil {
			if skipLastKey := len(keys) - 2; skipLast && skipLastKey >= 0 {
				return verifySequentialEntrySigsAtIndex(skipLastKey, keys, sigs)
			}
		}
	}

	return nil
}

func approveLastAdditionInDbFile(pubKey *btcec.PublicKey, key *btcec.PrivateKey, path string) error {
	// Make sure we're working with a good DB
	if err := verifyDbFile(path, true); err != nil {
		return err
	}

	keys, sigs, err := parseDbFile(path)
	if err != nil {
		return err
	}

	if len(keys) == 0 {
		return errors.New("The trustfile is empty")
	}

	// Make sure there's a pending action
	lastEntry := len(keys) - 1
	if err := verifySequentialEntrySigsAtIndex(lastEntry, keys, sigs); err == nil {
		return errors.New("No pending addition to approve")
	} else {
		if keys[lastEntry].Cmd != "+" {
			return errors.New("No pending addition to approve")
		}

		// Verify that the private key is correct
		if bytes.Compare(keys[lastEntry].DoubleSha256PubKeyBytes, sha256ByteSum(sha256ByteSum(pubKey.SerializeCompressed()))) != 0 {
			return errors.New("The supplied public key does not match the key to be approved")
		}

		// Get the content to be signed
		content, err := contentForEntryIndex(lastEntry, keys, sigs)
		if err != nil {
			return err
		}

		// Create a tmp
		file, err := ioutil.TempFile(os.TempDir(), "trustedb")
		if err != nil {
			return err
		}

		tpath := file.Name()
		defer os.Remove(file.Name())

		// Copy the trustfile
		if err := cp(tpath, path); err != nil {
			return err
		}
		// Reopen file append-only
		tfile, err := os.OpenFile(tpath, os.O_RDWR|os.O_APPEND, 0660)
		if err != nil {
			return err
		}

		// Create the signature
		w := bufio.NewWriter(tfile)

		sig, err := btcec.SignCompact(btcec.S256(), key, sha256ByteSum([]byte(content)), true)
		if err != nil {
			return err
		}
		_, ferr := fmt.Fprintln(w, strings.Join([]string{
			"s=",
			hex.EncodeToString(sig),
		}, " "))

		if ferr != nil {
			return ferr
		}

		if err := w.Flush(); err != nil {
			return err
		}

		tkeys, tsigs, err := parseDbFile(tpath)
		if err != nil {
			return err
		}

		if err := verifySequentialEntrySigsAtIndex(len(tkeys)-1, tkeys, tsigs); err == nil {
			sig, err := btcec.SignCompact(btcec.S256(), key, sha256ByteSum([]byte(pubKey.SerializeCompressed())), true)
			if err != nil {
				return err
			}

			_, ferr := fmt.Fprintln(w, strings.Join([]string{
				"k=",
				hex.EncodeToString(pubKey.SerializeCompressed()),
				hex.EncodeToString(sig),
			}, " "))
			if ferr != nil {
				return ferr
			}

			if err := w.Flush(); err != nil {
				return err
			}
		}

		// Copy the trustfile
		return cp(path, tpath)
	}
}

func addEntryToDbFile(key *btcec.PrivateKey, identifier string, path string) error {
	if err := verifyDbFile(path, false); err != nil {
		return err
	}

	path, err := homedir.Expand(path)
	if err != nil {
		return err
	}

	file, err := os.OpenFile(path, os.O_RDWR|os.O_APPEND, 0660)
	if err != nil {
		return err
	}
	defer file.Close()

	w := bufio.NewWriter(file)
	_, fileErr := fmt.Fprintln(w, strings.Join([]string{
		"=+",
		strings.Replace(identifier, " ", "", -1),
		hex.EncodeToString(sha256ByteSum(sha256ByteSum(key.PubKey().SerializeCompressed()))),
	}, " "))

	if fileErr != nil {
		return fileErr
	}

	return w.Flush()
}

func sha256ByteSum(b []byte) []byte {
	hasher := sha256.New()
	hasher.Write(b)

	return hasher.Sum(nil)
}

func parseKeyEntryLine(l string) (*KeyEntry, error) {
	f := strings.Fields(l)
	if len(f) != reflect.ValueOf(&KeyEntry{}).Elem().NumField()-1 {
		return nil, errors.New("Malformed Key Entry Line")
	}

	cmd, email, doubleSha256PubKeyHex := f[0], f[1], f[2]
	doubleSha256PubKeyBytes, _ := hex.DecodeString(doubleSha256PubKeyHex)
	keyEntry := KeyEntry{
		Cmd:                     cmd,
		Identifier:              email,
		DoubleSha256PubKeyBytes: doubleSha256PubKeyBytes,
	}

	return &keyEntry, nil
}

func parseSigEntryLines(lines []string) ([]SigEntry, error) {
	e := []SigEntry{}

	for _, l := range lines {
		f := strings.Fields(l)
		if len(f)-1 != reflect.ValueOf(&SigEntry{}).Elem().NumField() {
			return nil, errors.New("Malformed Sig Entry Line")
		}

		s := f[1]

		sigBytes, _ := hex.DecodeString(s)
		e = append(e, SigEntry{
			SigBytes: sigBytes,
		})
	}

	return e, nil
}

func parseDbFile(path string) ([]KeyEntry, [][]SigEntry, error) {
	path, err := homedir.Expand(path)
	if err != nil {
		return nil, nil, err
	}
	lines, err := readLines(path)
	if err != nil {
		return nil, nil, err
	}

	// Keep track of the log entries
	keyEntries := []KeyEntry{}
	sigEntries := [][]SigEntry{}

	if len(lines) == 0 {
		return keyEntries, sigEntries, nil
	}

	entriesWithSignatures := regexp.MustCompile("(?m)^=").Split(strings.Join(lines, "\n"), -1)
	// Remove the blank entry that is returned for some reason
	if len(entriesWithSignatures) > 0 && len(entriesWithSignatures[0]) == 0 {
		_, entriesWithSignatures = entriesWithSignatures[0], entriesWithSignatures[1:]
	}

	for _, entryWithSignatures := range entriesWithSignatures {
		keyEntryLine := regexp.MustCompile("(?m)^=[+-].*$").FindAllString(entryWithSignatures, -1)[0]
		disEntryLines := regexp.MustCompile("(?m)^d=.*$").FindAllString(entryWithSignatures, -1)
		sigEntryLines := regexp.MustCompile("(?m)^s=.*$").FindAllString(entryWithSignatures, -1)
		revEntryLines := regexp.MustCompile("(?m)^k=.*$").FindAllString(entryWithSignatures, -1)

		if len(revEntryLines) > 1 {
			return nil, nil, errors.New("Each KeyEntry must only reveal once")
		}

		keyEntry, err := parseKeyEntryLine(keyEntryLine)
		if err != nil {
			return nil, nil, err
		}

		sigEntries, err := parseSigEntryLines(sigEntryLines)
		if err != nil {
			return nil, nil, err
		}
	}

	return keyEntries, sigEntries, nil
}

func keyFromKeyFile(path string) (*btcec.PrivateKey, error) {
	path, err := homedir.Expand(path)
	if err != nil {
		return nil, err
	}
	lines, err := readLines(path)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		return nil, errors.New("No private key in keyfile")
	}
	keyBytes, err := hex.DecodeString(lines[0])
	k, _ := btcec.PrivKeyFromBytes(btcec.S256(), keyBytes)

	return k, nil
}

func main() {
	app := cli.NewApp()
	app.Name = "Trustedb"
	app.Usage = "Verifiable append-only file of trusted keys"
	app.Commands = []cli.Command{
		{
			Name:  "init",
			Usage: "Create a Trustedb file",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "trustfile",
					Usage:  "Path to your trustfile",
					EnvVar: "TRUSTEDB_TRUSTFILE",
				},
			},
			Action: func(c *cli.Context) {
				trustfile := c.String("trustfile")
				if len(trustfile) == 0 {
					fmt.Println("Please specify a trustfile")
					os.Exit(1)
				}
				if err := createTrustfile(trustfile); err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			},
		},
		{
			Name:  "approve",
			Usage: "Approve a pending key addition or removal request",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "keyfile",
					Usage:  "Path to your keyfile with a DER formatted private key",
					EnvVar: "TRUSTEDB_KEYFILE",
				},
				cli.StringFlag{
					Name:   "trustfile",
					Usage:  "Path to your trustfile",
					EnvVar: "TRUSTEDB_TRUSTFILE",
				},
			},
			Action: func(c *cli.Context) {
				keyfile := c.String("keyfile")
				if len(keyfile) == 0 {
					fmt.Println("Please specify a value for --keyfile")
					os.Exit(1)
				}
				trustfile := c.String("trustfile")
				if len(trustfile) == 0 {
					fmt.Println("Please specify a value for --trustfile")
					os.Exit(1)
				}

				if len(c.Args()) == 0 {
					fmt.Println("Please specify a hex encoded public key to approve")
					os.Exit(1)
				}
				hexPubKeyString := c.Args()[0]

				privKey, err := keyFromKeyFile(keyfile)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}

				pubKeyBytes, err := hex.DecodeString(hexPubKeyString)
				if err != nil {
					fmt.Println("Unable to parse Public Key")
					os.Exit(1)
				}

				if pubKey, err := btcec.ParsePubKey(pubKeyBytes, btcec.S256()); err != nil {
					fmt.Println(err)
					os.Exit(1)
				} else {
					if err := approveLastAdditionInDbFile(pubKey, privKey, trustfile); err != nil {
						fmt.Println(err)
						os.Exit(1)
					}
				}
			},
		},
		{
			Name:  "create-key",
			Usage: "Verify the integrity of a Trustedb file",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "keyfile",
					Usage:  "Path to store your DER formatted private key",
					EnvVar: "TRUSTEDB_KEYFILE",
				},
			},
			Action: func(c *cli.Context) {
				keyfile := c.String("keyfile")
				if len(keyfile) == 0 {
					fmt.Println("Please specify a keyfile")
				}
				err := createKeyfile(keyfile)
				if err != nil {
					fmt.Println("Error", err)
				}
			},
		},
		{
			Name:  "request",
			Usage: "Request modification to the specified Trustfile",
			Subcommands: []cli.Command{
				{
					Name:  "add",
					Usage: "Request the addition of a key to the Trustfile",
					Flags: []cli.Flag{
						cli.StringFlag{
							Name:   "keyfile",
							Usage:  "Path to your keyfile with a DER formatted private key",
							EnvVar: "TRUSTEDB_KEYFILE",
						},
						cli.StringFlag{
							Name:   "trustfile",
							Usage:  "Path to your trustfile",
							EnvVar: "TRUSTEDB_TRUSTFILE",
						},
						cli.StringFlag{
							Name:  "identifier",
							Usage: "Human readable identifier for the key owner",
						},
					},
					Action: func(c *cli.Context) {
						keyfile := c.String("keyfile")
						if len(keyfile) == 0 {
							fmt.Println("Please specify a value for --keyfile")
							os.Exit(1)
						}
						trustfile := c.String("trustfile")
						if len(trustfile) == 0 {
							fmt.Println("Please specify a value for --trustfile")
							os.Exit(1)
						}

						identifier := c.String("identifier")
						if len(identifier) == 0 {
							fmt.Println("Please specify a value for --identifier")
							os.Exit(1)
						}

						privKey, err := keyFromKeyFile(keyfile)
						if err != nil {
							fmt.Println(err)
							os.Exit(1)
						}

						if err := addEntryToDbFile(privKey, c.String("identifier"), trustfile); err != nil {
							fmt.Println(err)
							os.Exit(1)
						}
					},
				},
			},
		},
		{
			Name:  "verify",
			Usage: "Verify the integrity of a Trustedb file",
			Flags: []cli.Flag{
				cli.BoolFlag{
					Name:  "skiplast",
					Usage: "Skip threshold check on last entry",
				},
				cli.StringFlag{
					Name:   "trustfile",
					Usage:  "Path to your trustfile",
					EnvVar: "TRUSTEDB_TRUSTFILE",
				},
			},
			Action: func(c *cli.Context) {
				trustfile := c.String("trustfile")
				if len(trustfile) == 0 {
					fmt.Println("Please specify a trustfile")
					os.Exit(1)
				}

				if err := verifyDbFile(trustfile, c.Bool("skiplast")); err != nil {
					fmt.Println(err)
					os.Exit(1)
				} else {
					fmt.Println("Success!")
				}
			},
		},
	}
	app.Run(os.Args)
}
