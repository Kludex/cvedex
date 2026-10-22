// Package config stores cvedex credentials in $XDG_CONFIG_HOME/cvedex/config.json, by default
// ~/.config/cvedex/config.json, overridden field by field by CVE_API_URL, CVE_API_ORG,
// CVE_API_USER and CVE_API_KEY: the names cvelib uses, so existing CNA setups work unchanged.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/Kludex/cvedex/cveservices"
)

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

// Load reads the config file at path if there is one, then applies the environment overrides.
func Load(path string) (cveservices.Credentials, error) {
	var creds cveservices.Credentials
	data, err := os.ReadFile(path)
	switch {
	case errors.Is(err, fs.ErrNotExist):
	case err != nil:
		return creds, err
	default:
		if err := json.Unmarshal(data, &creds); err != nil {
			return creds, fmt.Errorf("%s: %w", path, err)
		}
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

// Save writes creds to the config file at path, readable by the owner only since it holds the API key.
func Save(path string, creds cveservices.Credentials) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, _ := json.MarshalIndent(creds, "", "  ") // all strings, so it cannot fail
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		return err
	}
	// WriteFile keeps the mode of a file that already exists.
	return os.Chmod(path, 0o600)
}
