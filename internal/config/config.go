// Package config stores cvedex credentials in $XDG_CONFIG_HOME/cvedex/config.json, by default
// ~/.config/cvedex/config.json, with the API key in the system keychain when there is one. They are
// overridden field by field by CVE_API_URL, CVE_API_ORG, CVE_API_USER and CVE_API_KEY: the names
// cvelib uses, so existing CNA setups work unchanged.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

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

// Load reads the config file at path if there is one, then applies the environment overrides. The
// API key may still be in the keychain: see Key.
func Load(path string) (cveservices.Credentials, error) {
	creds, err := read(path)
	if err != nil {
		return creds, err
	}
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
	return creds, nil
}

// Key returns the API key the system keychain holds for creds, or "" if it holds none.
func Key(creds cveservices.Credentials) (string, error) {
	key, err := keyring.Get(keychainService, account(creds))
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return "", fmt.Errorf("reading your API key from the system keychain: %w", err)
	}
	return key, nil
}

// Save stores the API key in the system keychain and the rest in the config file at path. Without a
// keychain, the key goes in the file, which is readable by the owner only either way. A GitHub
// repository has no key to store.
func Save(path string, creds cveservices.Credentials) (inKeychain bool, err error) {
	if previous, err := read(path); err == nil && previous.User != "" && account(previous) != account(creds) {
		_ = keyring.Delete(keychainService, account(previous)) // a key that is not there is fine
	}
	if creds.Key != "" && keyring.Set(keychainService, account(creds), creds.Key) == nil {
		creds.Key, inKeychain = "", true
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return inKeychain, err
	}
	data, _ := json.MarshalIndent(creds, "", "  ") // all strings, so it cannot fail
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return inKeychain, err
	}
	// WriteFile keeps the mode of a file that already exists.
	return inKeychain, os.Chmod(path, 0o600)
}

// Remove deletes the saved credentials, the API key in the keychain included, and returns what it
// removed. Nothing saved is not an error.
func Remove(path string) (cveservices.Credentials, error) {
	creds, err := read(path)
	if err != nil || creds == (cveservices.Credentials{}) {
		return creds, err
	}
	if creds.Key == "" {
		err := keyring.Delete(keychainService, account(creds))
		if err != nil && !errors.Is(err, keyring.ErrNotFound) {
			return creds, fmt.Errorf("removing your API key from the system keychain: %w", err)
		}
	}
	return creds, os.Remove(path)
}

func read(path string) (cveservices.Credentials, error) {
	var creds cveservices.Credentials
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return creds, nil
	}
	if err != nil {
		return creds, err
	}
	if err := json.Unmarshal(data, &creds); err != nil {
		return creds, fmt.Errorf("%s: %w", path, err)
	}
	return creds, nil
}

func account(creds cveservices.Credentials) string {
	return creds.User + " on " + creds.URL
}
