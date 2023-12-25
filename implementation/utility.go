package implementation

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/term"
)

// Read Username from CLI
func ReadUserName() (string, error) {
	fmt.Printf("Enter Username: ")

	var username string
	_, err := fmt.Scan(&username)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(username), nil
}

// Read Password securely from CLI
func readPassword() (string, error) {

	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}

	fmt.Println("")

	return strings.TrimSpace(string(password)), nil
}

// Generate a strong password for user
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

// Hash Password entered by user
func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// Read the Secret key from file if exists otherwise create a secret key and store it.
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

// Generate a Random Key
func generateRandomKey() [32]byte {
	var key [32]byte
	_, err := rand.Read(key[:])
	if err != nil {
		fmt.Println("Error generating random key:", err)
		os.Exit(1)
	}
	return key
}

// Generate Nonce for encryption/decryption of password
func generateNonce() *[24]byte {
	var nonce [24]byte
	_, err := rand.Read(nonce[:])
	if err != nil {
		fmt.Println("Error generating nonce:", err)
		os.Exit(1)
	}
	return &nonce
}

// Encrypt the password
func encryptPassword(password string, nonce *[24]byte) []byte {
	secretKey := readOrCreateKey()

	encrypted := secretbox.Seal(nil, []byte(password), nonce, &secretKey)
	return encrypted
}

// Decrypt the password
func decryptPassword(cipher []byte, nonce *[24]byte) (string, error) {
	secretKey := readOrCreateKey()

	decrypted, ok := secretbox.Open(nil, cipher, nonce, &secretKey)
	if !ok {
		return "", fmt.Errorf("decryption error")
	}

	return string(decrypted), nil
}

// Print Usage function
func PrintUsage() {
	fmt.Println("Usage:")
	fmt.Println("passlock <operation> [options]")
	fmt.Println("Operations:")
	fmt.Println("-add-password <tag> [-password=<password> | -generate]")
	fmt.Println("Create/Add a strong password for the specified tag.")
	fmt.Println("Options:")
	fmt.Println("	-password=<password>  Specify the password.")
	fmt.Println("	-generate             Generate a strong password.")

	fmt.Println("-update-password <tag> [-password=<password> | -generate]")
	fmt.Println("Update the password for the specified tag.")
	fmt.Println("Options:")
	fmt.Println("	-password=<password>  Specify the new password.")
	fmt.Println("	-generate             Generate a new strong password.")

	fmt.Println("-delete-password <tag>")
	fmt.Println("Delete the password for the specified tag.")

	fmt.Println("-get-password <tag>")
	fmt.Println("Get the password for the specified tag.")

	fmt.Println("-get-tags")
	fmt.Println("Get all tags.")

	fmt.Println("-help")
	fmt.Println("Display this help message.")
}

// Check if user is duplicate
func isDuplicate(users []User, username string) bool {
	duplicateUser := false

	for _, user := range users {
		if user.Username == username {
			duplicateUser = true
			break
		}
	}

	return duplicateUser
}

// Create a User password - First time using CLI
func createUser(username string) error {

	users, err := loadUsers()
	if err != nil {
		return err
	}

	if isDuplicate(users, username) {
		return errors.New("User already exists")
	}

	fmt.Print("Enter password for passlock: ")
	password, err := readPassword()
	if err != nil {
		return err
	}

	hashedPassword, err := hashPassword(password)
	if err != nil {
		return err
	}

	user := User{
		Username: username,
		Password: hashedPassword,
	}

	users = append(users, user)

	err = saveUsers(users)
	if err != nil {
		return err
	}

	return nil
}

// Authenticate User - Whenever using CLI commands
func authenticateUser(username string) (bool, error) {
	users, err := loadUsers()
	if err != nil {
		return false, err
	}

	var storedPassword string
	for _, user := range users {
		if user.Username == username {
			storedPassword = user.Password
			break
		}
	}

	if storedPassword == "" {
		return false, nil
	}

	fmt.Printf("Enter your password for %s: ", username)
	password, err := readPassword()
	if err != nil {
		return false, err
	}

	err = bcrypt.CompareHashAndPassword([]byte(storedPassword), []byte(password))
	if err != nil {
		return false, err
	}

	return true, nil
}
