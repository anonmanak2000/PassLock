package implementation

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"testing"

	"bou.ke/monkey"
	"github.com/stretchr/testify/assert"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/nacl/secretbox"
	"golang.org/x/term"
)

// Test Read Username method
func TestReadUserName(t *testing.T) {

	t.Run("Valid Username", func(t *testing.T) {

		mockInput := "JohnDoe"
		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)

		}
		w.Write([]byte(mockInput))
		w.Close()
		os.Stdin = r
		defer func() { os.Stdin = os.Stdin }()

		result, err := ReadUserName()

		assert.NoError(t, err)

		assert.EqualValues(t, []byte(mockInput), []byte(result))

	})

	t.Run("Invalid Username", func(t *testing.T) {

		r, w, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		w.Close()
		os.Stdin = r
		defer func() { os.Stdin = os.Stdin }()

		result, err := ReadUserName()

		assert.Error(t, err)

		assert.Empty(t, []byte(result))

	})

}

func TestReadPassword(t *testing.T) {

	mockErrorReadPassword := func(fd int) ([]byte, error) {
		return nil, errors.New("Error while reading password")
	}

	t.Run("Error during password input", func(t *testing.T) {

		patchErrorReadPassword := monkey.Patch(term.ReadPassword, mockErrorReadPassword)

		defer patchErrorReadPassword.Unpatch()

		password, err := readPassword()

		assert.Error(t, err)
		assert.Empty(t, password)
	})
}

// Test Generate Strong Password method
// MockRandReader is a mock implementation of the io.Reader interface for testing.
type mockRandReader struct {
	err error
}

// Read is the mocked method for io.Reader.Read.
func (m *mockRandReader) Read(p []byte) (n int, err error) {
	return 0, m.err
}

func TestGenerateStrongPassword(t *testing.T) {
	t.Run("Successful password generation", func(t *testing.T) {

		password, err := generateStrongPassword()

		assert.NoError(t, err)
		assert.Equal(t, 32, len(password)) // Ensure the correct length

	})

	t.Run("Error during random index generation", func(t *testing.T) {

		mockRandReader := &mockRandReader{err: fmt.Errorf("Error during random index generation")}
		oldRandReader := rand.Reader
		rand.Reader = mockRandReader
		defer func() {
			rand.Reader = oldRandReader
		}()

		password, err := generateStrongPassword()

		assert.Error(t, err)
		assert.Empty(t, password)
	})

}

// Test Hash Password method
func TestHashPassword(t *testing.T) {
	t.Run("Successfully Hash Password", func(t *testing.T) {
		mockPassword := "MockPassword"
		hashedPassword, err := hashPassword(mockPassword)

		assert.NoError(t, err)
		assert.NotEmpty(t, hashedPassword)
		assert.True(t, bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(mockPassword)) == nil, "Hashed Password and mock password donot match")
	})

	t.Run("Error while generating hashed password", func(t *testing.T) {
		mockPassword := "MockPassword"
		mockError := errors.New("Error while generating hashed password")
		mockGenerateFromPassword := func([]byte, int) ([]byte, error) {
			return nil, mockError
		}

		patchGeneratePassword := monkey.Patch(bcrypt.GenerateFromPassword, mockGenerateFromPassword)
		defer patchGeneratePassword.Unpatch()

		result, err := hashPassword(mockPassword)

		assert.Equal(t, "", result)
		assert.Equal(t, mockError, err)
	})
}

// Test Generate Random Key generation method
func TestGenerateRandomKey(t *testing.T) {
	t.Run("Successfully generate random key", func(t *testing.T) {
		mockRandomKey := generateRandomKey()
		assert.NotEmpty(t, mockRandomKey)
		assert.Len(t, mockRandomKey, 32)
	})

	t.Run("Error while generating random key", func(t *testing.T) {

		mockError := errors.New("Error while Generating Random Key")
		mockRandRead := func(b []byte) (int, error) {

			return 0, mockError
		}

		mockOSExit := func(code int) {
			assert.Equal(t, 1, code, "OS.Exit(1) called")
		}

		patchRandomReader := monkey.Patch(rand.Read, mockRandRead)
		patchOSExit := monkey.Patch(os.Exit, mockOSExit)

		defer func() {
			patchRandomReader.Unpatch()
			patchOSExit.Unpatch()
		}()

		_ = generateRandomKey()
	})
}

// Test Generate Nonce method
func TestGenerateNonce(t *testing.T) {
	t.Run("Successfully generate nonce", func(t *testing.T) {
		mockNonce := generateNonce()
		assert.NotEmpty(t, mockNonce)
		assert.Len(t, mockNonce, 24, "Nonce is of length 24")

	})
	t.Run("Error while generating nonce", func(t *testing.T) {

		mockError := errors.New("Error while Generating Nonce")
		mockRandRead := func(b []byte) (int, error) {

			return 0, mockError
		}

		mockOSExit := func(code int) {
			assert.Equal(t, 1, code, "OS.Exit(1) called")
		}

		patchRandomReader := monkey.Patch(rand.Read, mockRandRead)
		patchOSExit := monkey.Patch(os.Exit, mockOSExit)

		defer func() {
			patchRandomReader.Unpatch()
			patchOSExit.Unpatch()
		}()

		_ = generateNonce()
	})

}

// Test Encrypt Password method
func TestEncryptPassword(t *testing.T) {
	t.Run("Success Encrypt Password", func(t *testing.T) {
		mockReadOrCreateKey := func() [32]byte {
			var key [32]byte
			_, _ = rand.Read(key[:])

			return key
		}

		patchReadOrCreateKey := monkey.Patch(readOrCreateKey, mockReadOrCreateKey)

		defer patchReadOrCreateKey.Unpatch()

		mockPassword := "MockPassword"
		var mockNonce [24]byte
		_, _ = rand.Read(mockNonce[:])

		mockEncryptedPassword := encryptPassword(mockPassword, &mockNonce)

		assert.NotEmpty(t, mockEncryptedPassword)
	})

	t.Run("Error while generating Encrypted Password", func(t *testing.T) {
		mockReadOrCreateKey := func() [32]byte {
			var key [32]byte
			_, _ = rand.Read(key[:])

			return key
		}

		mockEncryption := func(out []byte, message []byte, nonce *[24]byte, key *[32]byte) []byte {
			var testPassword []byte

			_, _ = rand.Read(testPassword[:])

			return testPassword
		}

		patchReadOrCreateKey := monkey.Patch(readOrCreateKey, mockReadOrCreateKey)
		patchEncryption := monkey.Patch(secretbox.Seal, mockEncryption)

		defer func() {
			patchReadOrCreateKey.Unpatch()
			patchEncryption.Unpatch()
		}()

		mockPassword := "MockPassword"
		var mockNonce [24]byte
		_, _ = rand.Read(mockNonce[:])

		mockEncryptedPassword := encryptPassword(mockPassword, &mockNonce)

		assert.Empty(t, mockEncryptedPassword)
	})
}

// Test Decrypt Password method
func TestDecryptPassword(t *testing.T) {
	t.Run("Successfully Decrypt Password", func(t *testing.T) {
		mockReadOrCreateKey := func() [32]byte {
			var key [32]byte
			_, _ = rand.Read(key[:])

			return key
		}

		mockDecryption := func(out []byte, box []byte, nonce *[24]byte, key *[32]byte) ([]byte, bool) {
			var testPassword []byte = []byte("Test")

			return testPassword, true
		}

		patchReadOrCreateKey := monkey.Patch(readOrCreateKey, mockReadOrCreateKey)
		patchDecryption := monkey.Patch(secretbox.Open, mockDecryption)

		defer func() {
			patchReadOrCreateKey.Unpatch()
			patchDecryption.Unpatch()
		}()

		mockCipher := []byte("MockPassword")
		var mockNonce [24]byte
		_, _ = rand.Read(mockNonce[:])

		mockDecryptedPassword, err := decryptPassword(mockCipher, &mockNonce)

		assert.NoError(t, err)
		assert.NotEmpty(t, mockDecryptedPassword)
	})

	t.Run("Error while decrypting password", func(t *testing.T) {
		mockReadOrCreateKey := func() [32]byte {
			var key [32]byte
			_, _ = rand.Read(key[:])

			return key
		}

		mockDecryption := func(out []byte, box []byte, nonce *[24]byte, key *[32]byte) ([]byte, bool) {
			var testPassword []byte = []byte("")

			return testPassword, false
		}

		patchReadOrCreateKey := monkey.Patch(readOrCreateKey, mockReadOrCreateKey)
		patchDecryption := monkey.Patch(secretbox.Open, mockDecryption)

		defer func() {
			patchReadOrCreateKey.Unpatch()
			patchDecryption.Unpatch()
		}()

		mockCipher := []byte("MockPassword")
		var mockNonce [24]byte
		_, _ = rand.Read(mockNonce[:])

		mockDecryptedPassword, err := decryptPassword(mockCipher, &mockNonce)

		assert.Error(t, err)
		assert.Empty(t, mockDecryptedPassword)
	})
}

// Test ReadOrCreateKey method
func TestReadOrCreateKey(t *testing.T) {
	t.Run("Successfully create a new Key", func(t *testing.T) {
		mockReadFile := func(name string) ([]byte, error) {

			return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
		}

		mockRandomKey := func() [32]byte {
			var key [32]byte
			_, _ = rand.Read(key[:])

			return key
		}

		mockWriteFile := func(name string, data []byte, perm fs.FileMode) error {
			return nil
		}

		patchReadFile := monkey.Patch(os.ReadFile, mockReadFile)
		patchGenerateRandomKey := monkey.Patch(generateRandomKey, mockRandomKey)

		patchWriteFile := monkey.Patch(os.WriteFile, mockWriteFile)

		defer func() {
			patchReadFile.Unpatch()
			patchGenerateRandomKey.Unpatch()
			patchWriteFile.Unpatch()
		}()

		key := readOrCreateKey()

		assert.Len(t, key, 32)
	})

	t.Run("Error while reading key", func(t *testing.T) {
		mockReadFile := func(name string) ([]byte, error) {

			return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrClosed}
		}

		mockOSExit := func(code int) {
			assert.Equal(t, code, 1)
		}

		patchReadFile := monkey.Patch(os.ReadFile, mockReadFile)
		patchExit := monkey.Patch(os.Exit, mockOSExit)

		defer func() {
			patchReadFile.Unpatch()
			patchExit.Unpatch()
		}()

		_ = readOrCreateKey()
	})

	t.Run("Successfully read key from file", func(t *testing.T) {
		mockReadFile := func(name string) ([]byte, error) {

			fileData := make([]byte, 32)
			_, _ = rand.Read(fileData[:])
			return fileData, nil
		}

		patchReadFile := monkey.Patch(os.ReadFile, mockReadFile)

		defer func() {
			patchReadFile.Unpatch()

		}()

		key := readOrCreateKey()

		assert.NotEmpty(t, key)
		assert.Len(t, key, 32)
	})

	t.Run("Invalid key size", func(t *testing.T) {
		mockReadFile := func(name string) ([]byte, error) {

			fileData := make([]byte, 20)
			_, _ = rand.Read(fileData[:])
			return fileData, nil
		}
		mockOSExit := func(code int) {
			assert.Equal(t, code, 1)
		}

		patchReadFile := monkey.Patch(os.ReadFile, mockReadFile)
		patchExit := monkey.Patch(os.Exit, mockOSExit)

		defer func() {
			patchReadFile.Unpatch()
			patchExit.Unpatch()

		}()

		_ = readOrCreateKey()

	})

}

// Test PrintUsage method
func TestPrintUsage(t *testing.T) {
	PrintUsage()
}

// Test Create User method
func TestCreateUser(t *testing.T) {
	mockUserName := "TestUsername"

	mockReadPassword := func() (string, error) {
		return "TestPassword", nil
	}

	mockErrorReadPassword := func() (string, error) {
		return "", errors.New("Error while reading password")
	}

	mockHashPassword := func(password string) (string, error) {
		return "TestPasswordHash", nil
	}
	mockLoadUsers := func() ([]User, error) {
		return []User{}, nil
	}

	mockErrorLoadUsers := func() ([]User, error) {
		return nil, errors.New("Error while loading Users")
	}

	mockSaveUsers := func(users []User) error {
		return nil
	}

	mockErrorSaveUsers := func(users []User) error {
		return errors.New("Error while saving users")
	}

	t.Run("Successfully Create User", func(t *testing.T) {
		patchReadPassword := monkey.Patch(readPassword, mockReadPassword)
		patchHashPassword := monkey.Patch(hashPassword, mockHashPassword)
		patchLoadUsers := monkey.Patch(loadUsers, mockLoadUsers)
		patchSaveUsers := monkey.Patch(saveUsers, mockSaveUsers)

		defer func() {
			patchReadPassword.Unpatch()
			patchHashPassword.Unpatch()
			patchLoadUsers.Unpatch()
			patchSaveUsers.Unpatch()
		}()

		err := createUser(mockUserName)

		assert.NoError(t, err)
	})

	t.Run("Error while reading password", func(t *testing.T) {
		patchErrorReadPassword := monkey.Patch(readPassword, mockErrorReadPassword)

		defer patchErrorReadPassword.Unpatch()

		err := createUser(mockUserName)

		assert.Error(t, err)
	})

	t.Run("Error while loading users", func(t *testing.T) {
		patchReadPassword := monkey.Patch(readPassword, mockReadPassword)
		patchHashPassword := monkey.Patch(hashPassword, mockHashPassword)
		patchErrorLoadUsers := monkey.Patch(loadUsers, mockErrorLoadUsers)

		defer func() {
			patchReadPassword.Unpatch()
			patchHashPassword.Unpatch()
			patchErrorLoadUsers.Unpatch()
		}()

		err := createUser(mockUserName)

		assert.Error(t, err)
	})

	t.Run("Error while saving users", func(t *testing.T) {
		patchReadPassword := monkey.Patch(readPassword, mockReadPassword)
		patchHashPassword := monkey.Patch(hashPassword, mockHashPassword)
		patchLoadUsers := monkey.Patch(loadUsers, mockLoadUsers)
		patchErrorSaveUsers := monkey.Patch(saveUsers, mockErrorSaveUsers)

		defer func() {
			patchReadPassword.Unpatch()
			patchHashPassword.Unpatch()
			patchLoadUsers.Unpatch()
			patchErrorSaveUsers.Unpatch()
		}()

		err := createUser(mockUserName)

		assert.Error(t, err)
	})
}

// Test Authenticate User method
func TestAuthenticateUser(t *testing.T) {
	mockUsername := "TestUsername"

	mockLoadUsers := func() ([]User, error) {

		user := User{
			Username: mockUsername,
			Password: "TestPassword",
		}

		var users []User

		users = append(users, user)

		return users, nil
	}

	mockEmptyLoadUsers := func() ([]User, error) {
		return []User{}, nil
	}

	mockErrorLoadUsers := func() ([]User, error) {
		return nil, errors.New("Error while loading users")
	}

	mockReadPassword := func() (string, error) {
		return "TestPassword", nil
	}

	mockErrorReadPassword := func() (string, error) {
		return "", errors.New("Error while reading password")
	}

	mockCompareHashPassword := func(hashedPassword, password []byte) error {
		return nil
	}

	mockErrorCompareHashPassword := func(hashedPassword, password []byte) error {
		return errors.New("Error while Comparing hashed password and password entered by user")
	}

	t.Run("Successfully Authenticate User", func(t *testing.T) {
		patchLoadUsers := monkey.Patch(loadUsers, mockLoadUsers)
		patchReadPassword := monkey.Patch(readPassword, mockReadPassword)
		patchComparePassword := monkey.Patch(bcrypt.CompareHashAndPassword, mockCompareHashPassword)

		defer func() {
			patchLoadUsers.Unpatch()
			patchReadPassword.Unpatch()
			patchComparePassword.Unpatch()
		}()

		authenticated, err := authenticateUser(mockUsername)

		assert.NoError(t, err)
		assert.True(t, authenticated)
	})

	t.Run("User not found", func(t *testing.T) {
		patchLoadUsers := monkey.Patch(loadUsers, mockEmptyLoadUsers)

		defer func() {
			patchLoadUsers.Unpatch()

		}()

		authenticated, err := authenticateUser(mockUsername)

		assert.NoError(t, err)
		assert.False(t, authenticated)
	})

	t.Run("Error while loading users", func(t *testing.T) {
		patchErrorLoadUsers := monkey.Patch(loadUsers, mockErrorLoadUsers)

		defer patchErrorLoadUsers.Unpatch()

		authenticated, err := authenticateUser(mockUsername)

		assert.Error(t, err)
		assert.False(t, authenticated)
	})

	t.Run("Error while reading password", func(t *testing.T) {
		patchLoadUsers := monkey.Patch(loadUsers, mockLoadUsers)
		patchErrorReadPassword := monkey.Patch(readPassword, mockErrorReadPassword)

		defer func() {
			patchLoadUsers.Unpatch()
			patchErrorReadPassword.Unpatch()
		}()

		authenticated, err := authenticateUser(mockUsername)

		assert.Error(t, err)
		assert.False(t, authenticated)
	})

	t.Run("Error while comparing password", func(t *testing.T) {
		patchLoadUsers := monkey.Patch(loadUsers, mockLoadUsers)
		patchReadPassword := monkey.Patch(readPassword, mockReadPassword)
		patchErrorComparePassword := monkey.Patch(bcrypt.CompareHashAndPassword, mockErrorCompareHashPassword)

		defer func() {
			patchLoadUsers.Unpatch()
			patchReadPassword.Unpatch()
			patchErrorComparePassword.Unpatch()
		}()

		authenticated, err := authenticateUser(mockUsername)

		assert.Error(t, err)
		assert.False(t, authenticated)
	})
}
