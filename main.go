package main

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"

	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcutil/hdkeychain"
	"github.com/jawher/mow.cli"
	"github.com/mitchellh/go-homedir"

	// Autoload
	_ "github.com/joho/godotenv/autoload"
)

/*
 * Structs
 */
type SigEntry struct {
	SigBytes []byte
}

type KeyEntry struct {
	Cmd                     string
	Identifier              string
	DoubleSha256PubKeyBytes []byte
}

/*
 * Command Constants
 */
const ADDITION_COMMAND string = "+"
const REMOVAL_COMMAND string = "-"
const TRUSTFILE_NEWLINE string = "\n"

/*
 * File Operations
 * http://stackoverflow.com/a/16615559/301043
 */
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

/*
 * Copy a file from src to dst
 */
func cp(dst, src string) error {
	s, err := os.Open(src)
	if err != nil {
		return err
	}

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

/*
 * Identity Operations
 */
func extendedKeyFromKeyFile(path string) (*hdkeychain.ExtendedKey, error) {
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

	// Decode the seed and instantiate the keychain
	seed, err := hex.DecodeString(lines[0])
	key, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	child, _ := strconv.Atoi(lines[1])
	return key.Child(hdkeychain.HardenedKeyStart + uint32(child))
}

func createIdentity(path string) error {
	path, err := homedir.Expand(path)
	if err != nil {
		return err
	}

	lines, _ := readLines(path)
	if len(lines) > 0 {
		return errors.New("Won't overwrite file " + path)
	}

	// Make the directory if it doesn't exist
	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return err
	}

	file, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	defer file.Close()

	seed, err := hdkeychain.GenerateSeed(hdkeychain.RecommendedSeedLen)
	if err != nil {
		fmt.Println(err)
		return err
	}

	w := bufio.NewWriter(file)
	// Add the hex encoded seed to the file
	fmt.Fprintln(w, hex.EncodeToString(seed))
	// Current hardened index (e.g. m/0'), useful if the
	// user needs to change their identity
	fmt.Fprintln(w, "0")
	fmt.Fprintln(w, "trustedb") // Canary for future AES decrypt success

	key, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		fmt.Println(err)
		return err
	}

	identity, err := key.Child(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		fmt.Println(err)
		return err
	}

	printPublicIdentityFromExtendedKey(identity)

	return w.Flush()
}

func printPublicIdentityFromExtendedKey(key *hdkeychain.ExtendedKey) error {
	pubIdentity, err := key.Neuter()
	if err != nil {
		fmt.Println(err)
		return err
	}

	fmt.Println("Your Identity: " + pubIdentity.String())

	return nil
}

/**
 * Secure String Generation
 * https://elithrar.github.io/article/generating-secure-random-numbers-crypto-rand/
 */

/**
 * GenerateRandomBytes returns securely generated random bytes.
 * It will return an error if the system's secure random
 * number generator fails to function correctly, in which
 * case the caller should not continue.
 */
func generateRandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	// Note that err == nil only if we read len(b) bytes.
	if err != nil {
		return nil, err
	}

	return b, nil
}

/**
 * generateRandomString returns a URL-safe, base64 encoded
 * securely generated random string.
 * It will return an error if the system's secure random
 * number generator fails to function correctly, in which
 * case the caller should not continue.
 */
func generateRandomString(s int) (string, error) {
	b, err := generateRandomBytes(s)
	return base64.URLEncoding.EncodeToString(b), err
}

/*
 * Trustfile Operations
 */

/*
 * Create the trustfile at a specified path
 */
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

	// Generate 128 byte string, base64 encode
	token, err := generateRandomString(128)
	if err != nil {
		return err
	}

	w := bufio.NewWriter(file)
	fmt.Fprintln(w, token)

	return nil
}

/*
 * Verify the Trustfile, and make sure it is well formed
 */
func verifyDbFile(path string, skipLast bool) error {
	keys, sigs, err := parseDbFile(path)
	if err != nil {
		return err
	}

	if err := verifyNoDoubleAdd(keys); err != nil {
		return err
	}

	if err := verifyNoDoubleSignatures(keys, sigs); err != nil {
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

/*
 * Verify that each entry only has a single signature from each key
 */
func verifyNoDoubleSignatures(keys []KeyEntry, entrySigs [][]SigEntry) error {
	for i, sigs := range entrySigs {
		content, err := contentForEntryIndex(i, keys, entrySigs)
		if err != nil {
			return err
		}

		s := map[string]int{}
		for _, sig := range sigs {
			// Check that the signature is well formed and return the compact public key
			if pk, err := checkSigAndRecoverCompact(sig, content); err != nil {
				return err
			} else {
				// Get a string representation of the compact public key
				k := hex.EncodeToString(pk.SerializeCompressed())
				// Check that we haven't seen this key for this command
				// e.g. no double signs for the same command
				if _, ok := s[k]; ok {
					return errors.New("Double signature for entry")
				} else {
					// Add entry to map for key to mark it as used.
					s[k] = 1
				}
			}
		}
	}

	return nil
}

/*
 * Verify that an entry is only ever added once, unless it is removed.
 */
func verifyNoDoubleAdd(keys []KeyEntry) error {
	logKeys := map[string]int{}

	if len(keys) == 1 {
		if keys[0].Cmd == ADDITION_COMMAND {
			return nil
		} else {
			return errors.New("An entry must be added before it may be removed")
		}
	}

	for _, key := range keys {
		c := hex.EncodeToString(key.DoubleSha256PubKeyBytes)
		_, hasKey := logKeys[c]
		if hasKey {
			if key.Cmd == ADDITION_COMMAND {
				return errors.New("An entry must be removed before it may be added again")
			}
		} else {
			if key.Cmd == REMOVAL_COMMAND {
				return errors.New("An entry must be added before it may be removed")
			}
		}
		if key.Cmd == REMOVAL_COMMAND {
			delete(logKeys, c)
		} else if key.Cmd == ADDITION_COMMAND {
			logKeys[c] = 1
		}
	}

	return nil
}

/*
 * Verify that each signature sequentially signs all
 * of the lines above it's insertion point.
 */
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

/*
 * Get the content to sign for an entry index. Each of the signatures
 * sign the previous signatures, but they do not sign signatures for the
 * same entry. This way git merges are easier. NOTE: Not sure if this is a great idea.
 */
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
		if i > 0 {
			content += TRUSTFILE_NEWLINE
		}
		if entry.Cmd == ADDITION_COMMAND {
			content += strings.Join([]string{"=" + entry.Cmd, entry.Identifier, hex.EncodeToString(entry.DoubleSha256PubKeyBytes)}, "")
		} else if entry.Cmd == REMOVAL_COMMAND {
			content += strings.Join([]string{"=" + entry.Cmd, entry.Identifier}, "")
		}

		// Don't include the sigs in the last entry
		// Since that is what we're looking to sign
		if i == index {
			return content, nil
		}

		sigContent := ""
		for j, sig := range sigs[i] {
			if j > 0 {
				sigContent += TRUSTFILE_NEWLINE
			}
			if p, err := checkSigAndRecoverCompact(sig, sigContent); err == nil {
				sigContent += strings.Join([]string{"SigFrom", " ", hex.EncodeToString(p.SerializeCompressed()), " ", hex.EncodeToString(sig.SigBytes)}, "")
			}
		}
		content += sigContent
	}

	return content, nil
}

/*
 * Get the approved signers for a given index
 */
func signersForEntryIndex(index int, keys []KeyEntry, sigs [][]SigEntry) (map[string]bool, int, error) {
	if len(keys) == 0 {
		return map[string]bool{}, 1, nil
	}

	if index > len(keys)-1 || index < -1 {
		return map[string]bool{}, -1, errors.New("Index out of bounds")
	}

	// Special case for first bootstrap sig
	if len(keys) == 1 && len(sigs[0]) == 0 {
		return map[string]bool{}, 1, nil
	}

	signers := map[string]bool{}
	required := -1
	for i, entry := range keys {
		required = 3
		if len(signers) < required {
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
			return map[string]bool{}, -1, err
		}

		numSuccessfulSigs := 0
		for _, sig := range sigs[i] {
			if pk, err := checkSigAndRecoverCompact(sig, content); err == nil {
				_, ok := signers[hex.EncodeToString(doubleSha256Sum(pk.SerializeCompressed()))]
				if ok || (i == 0 && len(signers) == 0) {
					numSuccessfulSigs += 1
					if numSuccessfulSigs >= required {
						k := hex.EncodeToString(entry.DoubleSha256PubKeyBytes)
						if entry.Cmd == ADDITION_COMMAND {
							signers[k] = true
						} else if entry.Cmd == REMOVAL_COMMAND {
							delete(signers, k)
						}
					}
				}
			}
		}
	}

	return signers, required, nil
}

/*
 * Crypto Functions
 */

/*
 * Check the signature and return the compact public key
 */
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

/*
 * Check the signature
 */
func checkSig(sig SigEntry, content string, signers map[string]*btcec.PublicKey) bool {
	if _, err := checkSigAndRecoverCompact(sig, content); err == nil {
		return true
	} else {
		return false
	}
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
		if keys[lastEntry].Cmd != ADDITION_COMMAND {
			return errors.New("No pending addition to approve")
		}

		// Verify that the private key is correct
		if bytes.Compare(keys[lastEntry].DoubleSha256PubKeyBytes, doubleSha256Sum(pubKey.SerializeCompressed())) != 0 {
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

		// Check to make sure the file is correct, skiping the last row
		if err := verifyDbFile(tpath, true); err != nil {
			return err
		}

		// Copy the trustfile
		return cp(path, tpath)
	}
}

func approveLastRemovalInDbFile(pubKey *btcec.PublicKey, key *btcec.PrivateKey, path string) error {
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
		if keys[lastEntry].Cmd != REMOVAL_COMMAND {
			return errors.New("No pending removal to approve")
		}

		// Verify that the private key is correct
		if bytes.Compare(keys[lastEntry].DoubleSha256PubKeyBytes, doubleSha256Sum(pubKey.SerializeCompressed())) != 0 {
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

		// Check to make sure the file is correct, skiping the last row
		if err := verifyDbFile(tpath, true); err != nil {
			return err
		}

		// Copy the trustfile
		return cp(path, tpath)
	}
}

func addEntryToDbFile(key *hdkeychain.ExtendedKey, identifier string, path string) error {
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

	extended, err := key.Neuter()
	if err != nil {
		return err
	}

	pub, err := extended.ECPubKey()
	if err != nil {
		return err
	}

	w := bufio.NewWriter(file)
	_, fileErr := fmt.Fprintln(w, strings.Join([]string{
		ADDITION_COMMAND,
		strings.Replace(identifier, " ", "", -1),
		hex.EncodeToString(doubleSha256Sum(pub.SerializeCompressed())),
	}, " "))

	if fileErr != nil {
		return fileErr
	}

	return w.Flush()
}

func removeEntryFromDbFile(key *btcec.PrivateKey, identifier string, path string) error {
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
		"=-",
		strings.Replace(identifier, " ", "", -1),
		hex.EncodeToString(doubleSha256Sum(key.PubKey().SerializeCompressed())),
	}, " "))

	if fileErr != nil {
		return fileErr
	}

	return w.Flush()
}

func doubleSha256Sum(b []byte) []byte {
	return sha256ByteSum(sha256ByteSum(b))
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

	entriesWithSignatures := regexp.MustCompile("(?m)^=").Split(strings.Join(lines, TRUSTFILE_NEWLINE), -1)
	// The first element is reserved for configuration
	// we're not using that now, so just dispose of it
	if len(entriesWithSignatures) > 0 && len(entriesWithSignatures[0]) == 0 {
		_, entriesWithSignatures = entriesWithSignatures[0], entriesWithSignatures[1:]
	}

	for _, entryWithSignatures := range entriesWithSignatures {
		keyEntryLine := regexp.MustCompile("(?m)^[+-].*$").FindAllString(entryWithSignatures, -1)[0]
		sigEntryLines := regexp.MustCompile("(?m)^s=.*$").FindAllString(entryWithSignatures, -1)

		sigs, err := parseSigEntryLines(sigEntryLines)
		if err != nil {
			return nil, nil, err
		}
		sigEntries = append(sigEntries, sigs)

		keyEntry, err := parseKeyEntryLine(keyEntryLine)
		if err != nil {
			return nil, nil, err
		}
		keyEntries = append(keyEntries, *keyEntry)
	}

	return keyEntries, sigEntries, nil
}

func main() {
	cp := cli.App("trustedb", "Trustedb.")
	var (
		identityOpt = cli.StringOpt{
			Name:   "i identity",
			Value:  "~/.trustedb/identity",
			Desc:   "Location of identity",
			EnvVar: "TRUSTEDB_IDENTITY",
		}
		trustfileOpt = cli.StringOpt{
			Name:   "t trustfile",
			Value:  "./Trustfile",
			Desc:   "Location of Trustfile",
			EnvVar: "TRUSTEDB_TRUSTFILE",
		}
		signOpt = cli.BoolOpt{
			Name:      "s sign",
			Value:     false,
			HideValue: true,
			Desc:      "Sign Trustfile after command",
		}
	)
	cp.Command("init", "Create a Trustfile", func(cmd *cli.Cmd) {
		trustfile := cmd.String(trustfileOpt)
		cmd.Action = func() {
			if len(*trustfile) == 0 {
				fmt.Println("Please specify a trustfile")
				os.Exit(1)
			}
			if err := createTrustfile(*trustfile); err != nil {
				fmt.Println(err)
				os.Exit(1)
			}
		}
	})
	cp.Command("identity", "Manage your trustedb identity", func(ident *cli.Cmd) {
		ident.Command("create", "Create a new identity", func(create *cli.Cmd) {
			identity := create.String(identityOpt)
			create.Action = func() {
				if len(*identity) == 0 {
					fmt.Println("Please specify the location of your trustedb identity")
				}
				err := createIdentity(*identity)
				if err != nil {
					fmt.Println("Error", err)
				}
			}
		})
		ident.Command("show", "Show current identity", func(show *cli.Cmd) {
			identity := show.String(identityOpt)
			show.Action = func() {
				if len(*identity) == 0 {
					fmt.Println("Please specify the location of your trustedb identity")
				}
				key, err := extendedKeyFromKeyFile(*identity)
				if err != nil {
					fmt.Println("Error", err)
				}

				// Print the key
				printPublicIdentityFromExtendedKey(key)
			}
		})
	})
	cp.Command("signers", "Manage authorized signers", func(cmd *cli.Cmd) {
		cmd.Command("add", "Initiate the process of adding a signer", func(scmd *cli.Cmd) {
			pubkey := scmd.StringArg("IDENTITY", "", "xpub to add. Use `self` to add current identity.")
			addition := scmd.StringArg("IDENTIFIER", "", "Fiendly identifier (e.g. email, irc nick).")
			sign := scmd.Bool(signOpt)
			identity := scmd.String(identityOpt)
			trustfile := scmd.String(trustfileOpt)

			scmd.Action = func() {
				if _, err := os.Stat(*trustfile); os.IsNotExist(err) {
					fmt.Println("Trustfile not found at " + *trustfile)
					fmt.Println("You may run `trustedb init` to create a Trustfile")
					os.Exit(1)
				}

				if _, err := os.Stat(*trustfile); os.IsNotExist(err) {
					fmt.Println("Identity not found at " + *trustfile)
					fmt.Println("You may run `trustedb identity create` to create an identity")
					os.Exit(1)
				}

				var (
					extendedKey *hdkeychain.ExtendedKey
					err         error
				)
				if *pubkey != "self" {
					extendedKey, err = hdkeychain.NewKeyFromString(*pubkey)
				} else {
					privateKey, err := extendedKeyFromKeyFile(*identity)
					if err != nil {
						fmt.Println(err)
						os.Exit(1)
					}
					extendedKey, err = privateKey.Neuter()
				}

				if err != nil {
					fmt.Println(err)
					os.Exit(1)
				}

				fmt.Println(extendedKey.String())
				os.Exit(1)
				fmt.Println(*sign)
				if err := addEntryToDbFile(extendedKey, *addition, *trustfile); err != nil {
					fmt.Println(err)
					os.Exit(1)
				}
			}
		})

		cmd.Command("remove", "Initiate the process of removing a signer", func(cmd *cli.Cmd) {
			fmt.Println("start removing a signer")
		})

		cmd.Command("confirm", "Confirm an addition or revocation", func(cmd *cli.Cmd) {
			identity := cmd.String(cli.StringArg{Name: "IDENTIFIER", Value: "", Desc: "The public identifier to confirm"})
			fmt.Println(identity)
		})

		cmd.Command("status", "determine the status of a signer", func(cmd *cli.Cmd) {
			fmt.Println("status of key")
		})

		cmd.Command("list", "List the signers", func(cmd *cli.Cmd) {
			fmt.Println("List keys")
		})
	})

	cp.Command("verify", "Verify a signature against the Trustfile", func(cmd *cli.Cmd) {
		identity := cmd.String(cli.StringArg{Name: "IDENTIFIER", Value: "", Desc: "The public identifier to add"})
		fmt.Println(identity)
	})

	/*
		app := cli.NewApp()
		app.Name = "Trustedb"
		app.Usage = "Verifiable append-only file of trusted keys"
		app.Commands = []cli.Command{
			{
				Name:  "approve",
				Usage: "Approve a pending key addition or removal request",
				Subcommands: []cli.Command{
					{
						Name:  "addition",
						Usage: "Approve a pending addition",
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
						Name:  "removal",
						Usage: "Approve a pending removal",
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
								if err := approveLastRemovalInDbFile(pubKey, privKey, trustfile); err != nil {
									fmt.Println(err)
									os.Exit(1)
								}
							}
						},
					},
				},
			},
			{
				Name:  "create-key",
				Usage: "Create a keyfile",
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
						Name:  "addition",
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
					{
						Name:  "removal",
						Usage: "Request the removal of a key from the Trustfile",
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

							if err := removeEntryFromDbFile(privKey, c.String("identifier"), trustfile); err != nil {
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
			{
				Name:  "signers",
				Usage: "List the approved signers hashes",
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

					if err := verifyDbFile(trustfile, true); err != nil {
						fmt.Println(err)
						os.Exit(1)
					}

					keys, sigs, err := parseDbFile(trustfile)
					if err != nil {
						fmt.Println(err)
						os.Exit(1)
					}

					if signers, _, err := signersForEntryIndex(-1, keys, sigs); err != nil {
						fmt.Println(err)
						os.Exit(1)
					} else {
						for key, _ := range signers {
							fmt.Println(key)
						}
					}
				},
			},
			{
				Name:  "checksig",
				Usage: "Check that the signature comes from an approved deployer",
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

					if err := verifyDbFile(trustfile, true); err != nil {
						fmt.Println(err)
						os.Exit(1)
					}

					keys, sigs, err := parseDbFile(trustfile)
					if err != nil {
						fmt.Println(err)
						os.Exit(1)
					}

					if signers, _, err := signersForEntryIndex(-1, keys, sigs); err != nil {
						fmt.Println(err)
						os.Exit(1)
					} else {
						if len(signers) == 0 {
							fmt.Println("Signer not approved")
							os.Exit(1)
						}

						sig := SigEntry{}
						content := ""
						if len(c.Args()) == 0 {
							fmt.Println("Must specify the plaintext content and hex encoded signature")
							os.Exit(1)
						} else if len(c.Args()) == 1 {
							bytes, err := ioutil.ReadAll(os.Stdin)
							if len(bytes) == 0 {
								fmt.Println("Must specify the plaintext content and hex encoded signature")
								os.Exit(1)
							}
							content = string(bytes)
							sigs, err := parseSigEntryLines([]string{"s= " + c.Args()[0]})
							if err != nil {
								fmt.Println(err)
								os.Exit(1)
							}
							sig = sigs[0]
						} else if len(c.Args()) == 2 {
							content = c.Args()[0]
							sigs, err := parseSigEntryLines([]string{"s= " + c.Args()[1]})
							if err != nil {
								fmt.Println(err)
								os.Exit(1)
							}
							sig = sigs[0]
						}
						pk, err := checkSigAndRecoverCompact(sig, content)
						if err != nil {
							fmt.Println("Must specify the plaintext content and hex encoded signature")
							os.Exit(1)
						}
						if _, ok := signers[hex.EncodeToString(pk.SerializeCompressed())]; !ok {
							fmt.Println("Signer not approved")
							os.Exit(1)
						} else {
							fmt.Println("Success!")
							os.Exit(0)
						}
					}
				},
			},
		}
	*/
	cp.Run(os.Args)
}
