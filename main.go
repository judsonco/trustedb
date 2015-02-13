package main

import (
	"bufio"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/btcec"
	"github.com/codegangsta/cli"
	"github.com/mitchellh/go-homedir"
	"os"
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

				keys, sigs, err := parseDbFile(trustfile)
				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
				fmt.Println(keys, sigs)
			},
		},
	}
	app.Run(os.Args)
}
