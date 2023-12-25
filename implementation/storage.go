package implementation

import (
	"encoding/json"
	"os"
)

const PasswordFile = "passwords.json"
const KeyFile = "secret.key"
const UserFile = "users.json"

type EncryptedPasswordEntry struct {
	Tag      string   `json:"tag"`
	Cipher   []byte   `json:"cipher"`
	Username string   `json:"username"`
	Nonce    [24]byte `json:"nonce"`
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// File Operations:
// Updating Password Entries
func savePasswordEntry(entry EncryptedPasswordEntry) error {
	entries, err := loadPasswordEntries()
	if err != nil {
		return err
	}

	entries = append(entries, entry)

	return savePasswordEntries(entries)
}

// Saving Updated Password Entries in the file
func savePasswordEntries(entries []EncryptedPasswordEntry) error {
	fileContents, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		return err
	}

	err = os.WriteFile(PasswordFile, fileContents, 0644)
	if err != nil {
		return err
	}

	return nil
}

// Load Password Entries from file
func loadPasswordEntries() ([]EncryptedPasswordEntry, error) {
	fileContents, err := os.ReadFile(PasswordFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []EncryptedPasswordEntry{}, nil
		}
		return nil, err
	}

	var entries []EncryptedPasswordEntry
	err = json.Unmarshal(fileContents, &entries)
	if err != nil {
		return nil, err
	}

	return entries, nil
}

// Save Users in the file
func saveUsers(users []User) error {
	fileContents, err := json.MarshalIndent(users, "", "  ")
	if err != nil {
		return err
	}

	err = os.WriteFile(UserFile, fileContents, 0644)
	if err != nil {
		return err
	}

	return nil
}

// Load Users from the file
func loadUsers() ([]User, error) {
	fileContents, err := os.ReadFile(UserFile)
	if err != nil {
		if os.IsNotExist(err) {
			return []User{}, nil
		}
		return nil, err
	}

	var users []User
	err = json.Unmarshal(fileContents, &users)
	if err != nil {
		return nil, err
	}

	return users, nil
}
