package implementation

import (
	"fmt"
)

type PasswordManagerOperations interface {
	AddPasswordWithTag(string, string, bool) error
	GetAllTags()
	DeletePasswordWithTag(string) error
	UpdatePasswordWithTag(string, string, bool) error
	GetPasswordWithTag(string)
}

type PasswordManager struct {
	Username string
}

func NewPasswordManager() (*PasswordManager, error) {

	username, err := ReadUserName()
	if err != nil {
		fmt.Println("Error reading username: ", err)
		return &PasswordManager{}, err
	}

	authenticated, err := authenticateUser(username)

	if err != nil {
		fmt.Println("Error: ", err)
		return &PasswordManager{}, err
	}

	if !authenticated {
		fmt.Println("Creating a new user.")
		err := createUser(username)
		if err != nil {
			fmt.Println("Error creating user: ", err)
			return &PasswordManager{}, err
		}
	}
	return &PasswordManager{
		Username: username,
	}, nil
}

// Operations:
// 1. Add Password With Tag
func (pm *PasswordManager) AddPasswordWithTag(tag, password string, generate bool) error {

	entries, err := loadPasswordEntries()
	if err != nil {
		fmt.Println("Error:", err)
		return
	}

	for _, entry := range entries {
		if entry.Tag == tag{
			return errors.New("Tag already exists!!!")
		}
	}

	if generate {
		strongpasword, err := generateStrongPassword()
		if err != nil {
			fmt.Printf("Error while generating strong password. \n")
			return err
		}
		password = strongpasword
		fmt.Printf("Generated strong password: %s\n", strongpasword)

	} else if password == "" {
		return fmt.Errorf("password is required")
	}

	nonce := generateNonce()
	encryptedPassword := encryptPassword(password, nonce)

	entry := EncryptedPasswordEntry{
		Tag:      tag,
		Cipher:   encryptedPassword,
		Username: pm.Username,
		Nonce:    *nonce,
	}

	err := savePasswordEntry(entry)
	if err != nil {
		return err
	}

	return nil
}

// 2. Get All Tags
func (pm *PasswordManager) GetAllTags() {
	entries, err := loadPasswordEntries()
	if err != nil {
		fmt.Println("Error getting tags:", err)
		return
	}

	fmt.Println("All Tags:")
	for _, entry := range entries {
		fmt.Println(entry.Tag)
	}
}

// 3. Delete Password with Tag
func (pm *PasswordManager) DeletePasswordWithTag(tag string) error {
	entries, err := loadPasswordEntries()
	if err != nil {
		return err
	}

	var newEntries []EncryptedPasswordEntry
	deleted := false

	for _, entry := range entries {
		if entry.Tag == tag && entry.Username == pm.Username {
			deleted = true
			continue
		}
		newEntries = append(newEntries, entry)
	}

	if !deleted {
		return fmt.Errorf("password with tag '%s' not found", tag)
	}

	err = savePasswordEntries(newEntries)
	if err != nil {
		return err
	}

	fmt.Println("Password deleted successfully.")
	return nil
}

// 4. Update Password with Tag
func (pm *PasswordManager) UpdatePasswordWithTag(tag, password string, generate bool) error {
	if generate {
		strongpassword, err := generateStrongPassword()
		if err != nil {
			fmt.Printf("Error while generating strong password. \n")
			return err
		}
		password = strongpassword
		fmt.Printf("Generated strong password: %s\n", strongpassword)

	} else if password == "" {
		return fmt.Errorf("password is required")
	}

	nonce := generateNonce()
	encryptedPassword := encryptPassword(password, nonce)

	entry := EncryptedPasswordEntry{
		Tag:      tag,
		Cipher:   encryptedPassword,
		Username: pm.Username,
		Nonce:    *nonce,
	}

	err := savePasswordEntry(entry)
	if err != nil {
		return err
	}

	fmt.Println("Password updated successfully.")
	return nil
}

// 5. Get Password with a Tag
func (pm *PasswordManager) GetPasswordWithTag(tag string) {
	entries, err := loadPasswordEntries()
	if err != nil {
		fmt.Println("Error getting password:", err)
		return
	}

	for _, entry := range entries {
		if entry.Tag == tag && entry.Username == pm.Username {
			password, err := decryptPassword(entry.Cipher, &entry.Nonce)
			if err != nil {
				fmt.Println("Error getting password:", err)
				return
			}
			fmt.Printf("Password for tag '%s': %s\n", tag, password)
			return
		}
	}

	fmt.Printf("Password for tag '%s' not found\n", tag)
}
