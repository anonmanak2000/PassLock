package main

import (
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/nacl/secretbox"

	"golang.org/x/term"
)

const PasswordFile = "passwords.json"
const KeyFile = "secret.key"
const UserFile = "users.json"

type EncryptedPasswordEntry struct {
	Tag      string `json:"tag"`
	Cipher   []byte
	Username string
	Nonce    [24]byte
}

type User struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type PasswordManager struct {
	Username string
}

func NewPasswordManager(username string) *PasswordManager {
	return &PasswordManager{
		Username: username,
	}
}

func (pm *PasswordManager) hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

func (pm *PasswordManager) createUser() error {
	fmt.Print("Enter password for passlock: ")
	password, err := readPassword()
	if err != nil {
		return err
	}

	hashedPassword, err := pm.hashPassword(password)
	if err != nil {
		return err
	}

	user := User{
		Username: pm.Username,
		Password: hashedPassword,
	}

	users, err := pm.loadUsers()
	if err != nil {
		return err
	}

	users = append(users, user)

	err = pm.saveUsers(users)
	if err != nil {
		return err
	}

	return nil
}

func (pm *PasswordManager) authenticateUser() bool {
	users, err := pm.loadUsers()
	if err != nil {
		return false
	}

	var storedPassword string
	for _, user := range users {
		if user.Username == pm.Username {
			storedPassword = user.Password
			break
		}
	}

	if storedPassword == "" {
		return false
	}

	fmt.Printf("Enter your password for %s: ", pm.Username)
	password, err := readPassword()
	if err != nil {
		return false
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
	if err != nil {
		return false
	}

	return true
}

func (pm *PasswordManager) createStrongPassword(tag, password, username string, generate bool) error {
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
	encryptedPassword, err := pm.encryptPassword(password, nonce)
	if err != nil {
		return err
	}

	entry := EncryptedPasswordEntry{
		Tag:      tag,
		Cipher:   encryptedPassword,
		Username: username,
		Nonce:    *nonce,
	}

	err = pm.savePasswordEntry(entry)
	if err != nil {
		return err
	}

	fmt.Println("Strong password created successfully.")
	return nil
}

func (pm *PasswordManager) savePasswordEntry(entry EncryptedPasswordEntry) error {
	entries, err := pm.loadPasswordEntries()
	if err != nil {
		return err
	}

	entries = append(entries, entry)

	return pm.savePasswordEntries(entries)
}

func (pm *PasswordManager) savePasswordEntries(entries []EncryptedPasswordEntry) error {
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

func (pm *PasswordManager) loadPasswordEntries() ([]EncryptedPasswordEntry, error) {
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

func readOrCreateKey() [32]byte {
	key, err := os.ReadFile(KeyFile)
	if err != nil {
		// If the key file does not exist, generate a new key and save it
		if os.IsNotExist(err) {
			newKey := generateRandomKey()
			err := os.WriteFile(KeyFile, newKey[:], 0644)
			if err != nil {
				fmt.Println("Error creating key file:", err)
				os.Exit(1)
			}
			return newKey
		}

		fmt.Println("Error reading key file:", err)
		os.Exit(1)
	}

	if len(key) != 32 {
		fmt.Println("Error: Key file must contain exactly 32 bytes.")
		os.Exit(1)
	}

	var secretKey [32]byte
	copy(secretKey[:], key)

	return secretKey
}

func generateRandomKey() [32]byte {
	var key [32]byte
	_, err := rand.Read(key[:])
	if err != nil {
		fmt.Println("Error generating random key:", err)
		os.Exit(1)
	}
	return key
}

func (pm *PasswordManager) encryptPassword(password string, nonce *[24]byte) ([]byte, error) {
	secretKey := readOrCreateKey()

	encrypted := secretbox.Seal(nil, []byte(password), nonce, &secretKey)
	return encrypted, nil
}

func (pm *PasswordManager) decryptPassword(cipher []byte, nonce *[24]byte) (string, error) {
	secretKey := readOrCreateKey()

	decrypted, ok := secretbox.Open(nil, cipher, nonce, &secretKey)
	if !ok {
		return "", fmt.Errorf("decryption error")
	}

	return string(decrypted), nil
}

func (pm *PasswordManager) saveUsers(users []User) error {
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

func (pm *PasswordManager) loadUsers() ([]User, error) {
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

func (pm *PasswordManager) getAllTags() {
	entries, err := pm.loadPasswordEntries()
	if err != nil {
		fmt.Println("Error getting tags:", err)
		return
	}

	fmt.Println("All Tags:")
	for _, entry := range entries {
		fmt.Println(entry.Tag)
	}
}

func (pm *PasswordManager) addPasswordWithTag(tag, password, username string) error {
	if password == "" {
		return fmt.Errorf("password is required")
	}

	nonce := generateNonce()
	encryptedPassword, err := pm.encryptPassword(password, nonce)
	if err != nil {
		return err
	}

	entry := EncryptedPasswordEntry{
		Tag:      tag,
		Cipher:   encryptedPassword,
		Username: username,
		Nonce:    *nonce,
	}

	err = pm.savePasswordEntry(entry)
	if err != nil {
		return err
	}

	fmt.Println("Password added successfully.")
	return nil
}

func (pm *PasswordManager) updatePasswordWithTag(tag, password, username string, generate bool) error {
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
	encryptedPassword, err := pm.encryptPassword(password, nonce)
	if err != nil {
		return err
	}

	entry := EncryptedPasswordEntry{
		Tag:      tag,
		Cipher:   encryptedPassword,
		Username: username,
		Nonce:    *nonce,
	}

	err = pm.savePasswordEntry(entry)
	if err != nil {
		return err
	}

	fmt.Println("Password updated successfully.")
	return nil
}

func (pm *PasswordManager) deletePasswordWithTag(tag, username string) error {
	entries, err := pm.loadPasswordEntries()
	if err != nil {
		return err
	}

	var newEntries []EncryptedPasswordEntry
	deleted := false

	for _, entry := range entries {
		if entry.Tag == tag && entry.Username == username {
			deleted = true
			continue
		}
		newEntries = append(newEntries, entry)
	}

	if !deleted {
		return fmt.Errorf("password with tag '%s' not found", tag)
	}

	err = pm.savePasswordEntries(newEntries)
	if err != nil {
		return err
	}

	fmt.Println("Password deleted successfully.")
	return nil
}

func (pm *PasswordManager) getPasswordWithTag(tag, username string) {
	entries, err := pm.loadPasswordEntries()
	if err != nil {
		fmt.Println("Error getting password:", err)
		return
	}

	for _, entry := range entries {
		if entry.Tag == tag && entry.Username == username {
			password, err := pm.decryptPassword(entry.Cipher, &entry.Nonce)
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

func readUserName() (string, error) {
	fmt.Printf("Enter Username: ")

	var username string
	_, err := fmt.Scan(&username)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(username), nil
}

func readPassword() (string, error) {
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}

	fmt.Println("") // Print a newline after password input for better formatting

	return strings.TrimSpace(string(password)), nil
}

func generateStrongPassword() (string, error) {
	const length = 32
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:'\",.<>/?`~"
	password := make([]byte, length)

	for i := range password {
		randomIndex, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		password[i] = charset[randomIndex.Int64()]
	}

	return string(password), nil
}

func generateNonce() *[24]byte {
	var nonce [24]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		fmt.Println("Error generating nonce:", err)
		os.Exit(1)
	}
	return &nonce
}

func printUsage() {
	fmt.Println("Usage:")
	fmt.Println("passlock <operation> [options]")
	fmt.Println("Operations:")
	fmt.Println("-create-strong-password <tag> [-password=<password> | -generate]")
	fmt.Println("	- Create a strong password for the specified tag.")
	fmt.Println("	Options:")
	fmt.Println("		-password=<password>  Specify the password.")
	fmt.Println("		-generate             Generate a strong password.")
	fmt.Println("-add-password <tag> -password=<password>")
	fmt.Println("	- Add a password for the specified tag.")
	fmt.Println("-update-password <tag> [-password=<password> | -generate]")
	fmt.Println("	- Update the password for the specified tag.")
	fmt.Println("	Options:")
	fmt.Println("		-password=<password>  Specify the new password.")
	fmt.Println("		-generate             Generate a new strong password.")
	fmt.Println("-delete-password <tag>")
	fmt.Println("	- Delete the password for the specified tag.")
	fmt.Println("-get-password <tag>")
	fmt.Println("	- Get the password for the specified tag.")
	fmt.Println("-get-tags")
	fmt.Println("	- Get all tags.")
	fmt.Println("-help")
	fmt.Println("	- Display this help message.")
}

func main() {
	if len(os.Args) < 2 || os.Args[1] == "-help" {
		printUsage()
		return
	}

	username, err := readUserName()
	if err != nil {
		fmt.Println("Error reading username: ", err)
		return
	}

	operation := os.Args[1]
	pm := NewPasswordManager(username)

	if !pm.authenticateUser() {
		fmt.Println("Creating a new user.")
		err := pm.createUser()
		if err != nil {
			fmt.Println("Error creating user:", err)
			return
		}
	}

	switch operation {
	case "-create-strong-password":
		var tag, password string
		var generate bool

		flagSet := flag.NewFlagSet("create-strong-password", flag.ExitOnError)
		flagSet.StringVar(&tag, "tag", "", "Specify the tag.")
		flagSet.StringVar(&password, "password", "", "Specify the password.")
		flagSet.BoolVar(&generate, "generate", false, "Generate a strong password.")
		flagSet.Parse(os.Args[2:])

		err := pm.createStrongPassword(tag, password, username, generate)
		if err != nil {
			fmt.Println("Error:", err)
		}
	case "-add-password":
		var tag, password string

		flagSet := flag.NewFlagSet("add-password", flag.ExitOnError)
		flagSet.StringVar(&tag, "tag", "", "Specify the tag.")
		flagSet.StringVar(&password, "password", "", "Specify the password.")
		flagSet.Parse(os.Args[2:])

		err := pm.addPasswordWithTag(tag, password, username)
		if err != nil {
			fmt.Println("Error:", err)
		}
	case "-update-password":
		var tag, password string
		var generate bool

		flagSet := flag.NewFlagSet("update-password", flag.ExitOnError)
		flagSet.StringVar(&tag, "tag", "", "Specify the tag.")
		flagSet.StringVar(&password, "password", "", "Specify the new password.")
		flagSet.BoolVar(&generate, "generate", false, "Generate a new strong password.")
		flagSet.Parse(os.Args[2:])

		err := pm.updatePasswordWithTag(tag, password, username, generate)
		if err != nil {
			fmt.Println("Error:", err)
		}
	case "-delete-password":
		var tag string
		flagSet := flag.NewFlagSet("delete-password", flag.ExitOnError)
		flagSet.StringVar(&tag, "tag", "", "Specify the tag.")
		flagSet.Parse(os.Args[2:])

		err := pm.deletePasswordWithTag(tag, username)
		if err != nil {
			fmt.Println("Error:", err)
		}
	case "-get-password":
		var tag string

		flagSet := flag.NewFlagSet("get-password", flag.ExitOnError)
		flagSet.StringVar(&tag, "tag", "", "Specify the tag.")
		flagSet.Parse(os.Args[2:])

		pm.getPasswordWithTag(tag, username)
	case "-get-tags":
		pm.getAllTags()
	default:
		fmt.Println("Invalid operation. Please use -help command to see all options.")
	}
}
