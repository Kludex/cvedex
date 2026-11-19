// Package config stores the accounts cvedex is logged in to in $XDG_CONFIG_HOME/cvedex/config.json,
// by default ~/.config/cvedex/config.json, with each API key in the system keychain when there is
// one. The account in use is overridden field by field by CVE_API_URL, CVE_API_ORG, CVE_API_USER and
// CVE_API_KEY: the names cvelib uses, so existing CNA setups work unchanged.
package config

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"

	"github.com/zalando/go-keyring"

	"github.com/Kludex/cvedex/cveservices"
)

const keychainService = "cvedex"

// Path returns where the config file lives, whether or not it exists.
func Path() (string, error) {
	if dir := os.Getenv("XDG_CONFIG_HOME"); dir != "" {
		return filepath.Join(dir, "cvedex", "config.json"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "cvedex", "config.json"), nil
}

// File is what the config file holds: the account in use, and the others cvedex is logged in to.
type File struct {
	cveservices.Credentials
	Others []cveservices.Credentials `json:"others,omitempty"`
}

// Accounts lists every account in the file, in an order that does not depend on which is in use.
func (f File) Accounts() []cveservices.Credentials {
	accounts := slices.DeleteFunc(append(slices.Clone(f.Others), f.Credentials),
		func(c cveservices.Credentials) bool { return c.User == "" })
	slices.SortFunc(accounts, func(a, b cveservices.Credentials) int {
		return cmp.Or(cmp.Compare(a.URL, b.URL), cmp.Compare(a.User, b.User))
	})
	return accounts
}

// Read reads the config file at path. A file that is not there is an empty one.
func Read(path string) (File, error) {
	var f File
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return f, nil
	}
	if err != nil {
		return f, err
	}
	if err := json.Unmarshal(data, &f); err != nil {
		return f, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

// Env applies the environment overrides to creds. The API key may still be in the keychain: see Key.
func Env(creds cveservices.Credentials) cveservices.Credentials {
	for env, field := range map[string]*string{
		"CVE_API_URL":  &creds.URL,
		"CVE_API_ORG":  &creds.Org,
		"CVE_API_USER": &creds.User,
		"CVE_API_KEY":  &creds.Key,
	} {
		if value := os.Getenv(env); value != "" {
			*field = value
		}
	}
	return creds
}

// Key returns the API key the system keychain holds for creds, or "" if it holds none.
func Key(creds cveservices.Credentials) (string, error) {
	key, err := keyring.Get(keychainService, account(creds))
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return "", fmt.Errorf("reading your API key from the system keychain: %w", err)
	}
	return key, nil
}

// Save puts creds in use, next to the accounts already there. The API key goes in the system
// keychain and the rest in the config file at path. Without a keychain, the key goes in the file,
// which is readable by the owner only either way. A GitHub repository has no key to store.
func Save(path string, creds cveservices.Credentials) (inKeychain bool, err error) {
	saved, _ := Read(path) // a file nobody can read is replaced
	others := slices.DeleteFunc(saved.Accounts(), func(c cveservices.Credentials) bool {
		return account(c) == account(creds)
	})
	if creds.Key != "" && keyring.Set(keychainService, account(creds), creds.Key) == nil {
		creds.Key, inKeychain = "", true
	}
	return inKeychain, write(path, File{creds, others})
}

// Use puts account number n of saved.Accounts, counted from 1, in use, and returns it.
func Use(path string, saved File, n int) (cveservices.Credentials, error) {
	accounts := saved.Accounts()
	if n < 1 || n > len(accounts) {
		return cveservices.Credentials{}, fmt.Errorf("there is no account %d, see cvedex accounts", n)
	}
	chosen := accounts[n-1]
	return chosen, write(path, File{chosen, slices.Delete(accounts, n-1, n)})
}

// Remove forgets the account in use, its API key in the keychain included, and returns it. The
// first of the others, if any, is then the one in use. Nothing saved is not an error.
func Remove(path string) (cveservices.Credentials, error) {
	saved, err := Read(path)
	creds := saved.Credentials
	if err != nil || creds == (cveservices.Credentials{}) {
		return creds, err
	}
	if creds.Key == "" {
		err := keyring.Delete(keychainService, account(creds))
		if err != nil && !errors.Is(err, keyring.ErrNotFound) {
			return creds, fmt.Errorf("removing your API key from the system keychain: %w", err)
		}
	}
	if len(saved.Others) == 0 {
		return creds, os.Remove(path)
	}
	return creds, write(path, File{saved.Others[0], saved.Others[1:]})
}

func write(path string, f File) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(f, "", "  ") // all strings, so it cannot fail
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return err
	}
	// WriteFile keeps the mode of a file that already exists.
	return os.Chmod(path, 0o600)
}

func account(creds cveservices.Credentials) string {
	return creds.User + " on " + creds.URL
}
