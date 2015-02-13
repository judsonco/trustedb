package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/codegangsta/cli"
	"github.com/mitchellh/go-homedir"

	"os"
	"regexp"
)

// GenericFlag is the flag type for types implementing Generic
type SigEntry struct {
	PubKey string
	Sig    string
}

type KeyEntry struct {
	Cmd        string
	Identifier string
	PubKey     string
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

func verifyNoDoubleAdd(keys []KeyEntry) error {
	logKeys := map[string]int{}
	logIdentifiers := map[string]int{}
	for _, key := range keys {
		t, err := hex.DecodeString(key.PubKey)
		if err != nil {
			return err
		}
		p, err := btcec.ParsePubKey(t, btcec.S256())
		if err != nil {
			return err
		}
		c := hex.EncodeToString(p.SerializeCompressed())
		e := strings.ToLower(key.Identifier)
		_, hasKey := logKeys[c]
		_, hasIdentifier := logIdentifiers[e]
		if hasKey || hasIdentifier {
			if key.Cmd == "+" {
				return errors.New("An entry must be removed before it may be added again")
			}
		} else {
			if key.Cmd == "-" {
				return errors.New("An entry must be added before it may be removed")
			}
		}
		if key.Cmd == "-" {
			delete(logIdentifiers, e)
			delete(logKeys, c)
		} else if key.Cmd == "+" {
			logIdentifiers[e] = 1
			logKeys[c] = 1
		}
	}

	return nil
}

func verifyDbFile(path string, skipLast bool) error {
	keys, _, err := parseDbFile(path)
	if err != nil {
		return err
	}

	if err := verifyNoDoubleAdd(keys); err != nil {
		return err
	}

	return nil
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

	keyEntries := []KeyEntry{}
	sigEntries := [][]SigEntry{}
	a := regexp.MustCompile("(?m)^=").Split(strings.Join(lines, "\n"), -1)
	entriesWithSignatures := []string{}
	// Remove the blank entry that is matched
	if len(a) > 0 && len(a[0]) == 0 {
		_, entriesWithSignatures = a[0], a[1:]
	} else {
		entriesWithSignatures = a
	}
	for _, entryWithSignatures := range entriesWithSignatures {
		a := regexp.MustCompile("(?m)^").Split(entryWithSignatures, -1)
		entryLine, sigLines := a[0], a[1:]
		f := strings.Fields(entryLine)
		cmd, email, pubkey := f[0], f[1], f[2]
		keyEntries = append(keyEntries, KeyEntry{
			Cmd:        cmd,
			Identifier: email,
			PubKey:     pubkey,
		})
		sigs := []SigEntry{}
		for _, sigLine := range sigLines {
			f := strings.Fields(sigLine)
			pubKey, sig := f[1], f[2]
			sigs = append(sigs, SigEntry{
				PubKey: pubKey,
				Sig:    sig,
			})
		}
		sigEntries = append(sigEntries, sigs)
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

				err := verifyDbFile(trustfile, c.Bool("skiplast"))
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			},
		},
		{
			Name:  "approve",
			Usage: "Approve the addition of a key",
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:   "keyfile",
					Usage:  "Path to your keyfile with a DER formatted private key",
					EnvVar: "TRUSTEDB_KEYFILE",
				},
			},
			Action: func(c *cli.Context) {
				fmt.Println("verifying ", c.Args().First())
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
			Usage: "Approve the addition of a key",
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
					fmt.Println("Please specify a keyfile")
					os.Exit(1)
				}
				trustfile := c.String("trustfile")
				if len(trustfile) == 0 {
					fmt.Println("Please specify a trustfile")
					os.Exit(1)
				}
				privKey, err := keyFromKeyFile(keyfile)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				fmt.Println(trustfile)
				fmt.Println(hex.EncodeToString(privKey.PubKey().SerializeCompressed()))
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
