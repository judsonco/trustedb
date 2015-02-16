package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
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
	PubKeyBytes []byte
	SigBytes    []byte
}

type KeyDiscoveryRevealEntry struct {
	PubKeyBytes []byte
}

type KeyDiscoveryEntry struct {
	SignerPubKeyBytes []byte
	Sha256PubKeyBytes []byte
	SigBytes          []byte
}

type KeyEntry struct {
	Cmd                     string
	Identifier              string
	DoubleSha256PubKeyBytes []byte
	SelfSigBytes            []byte
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

func verifySequentialEntrySigs(keys []KeyEntry, sigs [][]SigEntry) error {
	content := ""
	signers := map[string]*btcec.PublicKey{}
	for i, entry := range keys {
		fmt.Println(entry)
		// Make sure the content is the same
		pk, _ := btcec.ParsePubKey(entry.DiscoveryEntry.PubKeyBytes, btcec.S256())
		compHex := hex.EncodeToString(pk.SerializeCompressed())
		if i > 0 {
			content += "\n"
		}
		content += strings.Join([]string{"=", entry.Cmd, " ", entry.Identifier, " ", compHex}, "")

		// Special case for the first key. So you can approve yourself
		if len(signers) == 0 {
			signers[compHex] = pk
		}

		req := 2
		if len(signers) < 2 {
			req = len(signers)
		}
		numSuccessfulSigs := 0
		sigContent := ""
		fmt.Println(sigs[i])
		for j, sig := range sigs[i] {
			if j > 0 {
				sigContent += "\n"
			}
			sigContent += strings.Join([]string{"SigFrom", " ", hex.EncodeToString(sig.PubKeyBytes), " ", hex.EncodeToString(sig.SigBytes)}, "")
			btcecSig, err := btcec.ParseDERSignature(sig.SigBytes, btcec.S256())
			if err != nil {
				return err
			}
			contentBytes := []byte(content)

			hasher := sha256.New()
			hasher.Write(contentBytes)
			contentSha := hasher.Sum(nil)

			fmt.Println(content, len(content))
			fmt.Println(hex.EncodeToString(contentSha))

			if pk, ok := signers[hex.EncodeToString(sig.PubKeyBytes)]; ok {
				if btcecSig.Verify(contentSha, pk) {
					numSuccessfulSigs += 1
					fmt.Println("SuccessSig")
					if numSuccessfulSigs >= req {
						signers[hex.EncodeToString(pk.SerializeCompressed())] = pk
					}
				}
			}
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

	if err := verifySequentialEntrySigs(keys, sigs); err != nil {
		return err
	}

	return nil
}

func addEntryToDbFile(key btcec.PrivateKey, identifier string, path string) error {
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
	if len(f) != reflect.ValueOf(&KeyEntry{}).Elem().NumField() {
		return nil, errors.New("Malformed Key Entry Line")
	}

	cmd, email, doubleSha256PubKeyHex, selfsig := f[0], f[1], f[2], f[3]
	doubleSha256PubKeyBytes, _ := hex.DecodeString(doubleSha256PubKeyHex)
	selfSigBytes, _ := hex.DecodeString(selfsig)
	keyEntry := KeyEntry{
		Cmd:                     cmd,
		Identifier:              email,
		DoubleSha256PubKeyBytes: doubleSha256PubKeyBytes,
		SelfSigBytes:            selfSigBytes,
	}

	return &keyEntry, nil
}

func parseSigEntryLines(lines []string) ([]SigEntry, error) {
	e := []SigEntry{}

	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) != reflect.ValueOf(&SigEntry{}).Elem().NumField() {
			return nil, errors.New("Malformed Sig Entry Line")
		}

		p, s := f[1], f[2]

		pubKeyBytes, _ := hex.DecodeString(p)
		sigBytes, _ := hex.DecodeString(s)
		e = append(e, SigEntry{
			PubKeyBytes: pubKeyBytes,
			SigBytes:    sigBytes,
		})
	}

	return e, nil
}

func parseKeyDiscoveryLines(lines []string) ([]KeyDiscoveryEntry, error) {
	e := []KeyDiscoveryEntry{}

	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) != reflect.ValueOf(&KeyDiscoveryEntry{}).Elem().NumField() {
			return nil, errors.New("Malformed Key Discovery Line")
		}

		pubKey, sha256PubKey, sig := f[1], f[2], f[3]

		pubKeyBytes, _ := hex.DecodeString(pubKey)
		sha256PubKeyBytes, _ := hex.DecodeString(sha256PubKey)
		sigBytes, _ := hex.DecodeString(sig)

		e = append(e, KeyDiscoveryEntry{
			SignerPubKeyBytes: pubKeyBytes,
			Sha256PubKeyBytes: sha256PubKeyBytes,
			SigBytes:          sigBytes,
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
	//disEntries := [][]KeyDiscoveryEntry{}

	if len(lines) == 0 {
		return keyEntries, sigEntries, nil
	}
	fmt.Println(lines[0])

	entriesWithSignatures := regexp.MustCompile("(?m)^=").Split(strings.Join(lines, "\n"), -1)
	// Remove the blank entry that is matched
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

		fmt.Println(keyEntry, disEntryLines, sigEntries, revEntryLines)
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
					fmt.Println("Please specify a public key to approve")
					os.Exit(1)
				}
				pubKey := c.Args()[0]

				if len(identifier) == 0 {
					fmt.Println("Please specify a value for --identifier")
					os.Exit(1)
				}
				privKey, err := keyFromKeyFile(keyfile)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
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

						if err := addEntryToDbFile(*privKey, c.String("identifier"), trustfile); err != nil {
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
