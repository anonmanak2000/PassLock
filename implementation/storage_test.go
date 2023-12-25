package implementation

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"testing"

	"bou.ke/monkey"
	"github.com/stretchr/testify/assert"
)

// Test Save Password Entry method
func TestSavePasswordEntry(t *testing.T) {

	var mockNonce [24]byte
	_, _ = rand.Read(mockNonce[:])

	mockPasswordEntry := EncryptedPasswordEntry{
		Tag:      "TestTag",
		Cipher:   []byte("TestCipher"),
		Username: "TestUsername",
		Nonce:    mockNonce,
	}

	mockLoadPasswordEntries := func() ([]EncryptedPasswordEntry, error) {
		return []EncryptedPasswordEntry{}, nil
	}

	mockErrorLoadPasswordEntries := func() ([]EncryptedPasswordEntry, error) {
		return nil, errors.New("Error while loading password entries")
	}

	mockSavePasswordEntries := func(entries []EncryptedPasswordEntry) error {
		return nil
	}

	mockErrorSavePasswordEntries := func(entries []EncryptedPasswordEntry) error {
		return errors.New("Error while saving password entries")
	}

	t.Run("Successfully save password entry", func(t *testing.T) {
		patchLoadPasswordEntries := monkey.Patch(loadPasswordEntries, mockLoadPasswordEntries)
		patchSavePasswordEntries := monkey.Patch(savePasswordEntries, mockSavePasswordEntries)

		defer func() {
			patchLoadPasswordEntries.Unpatch()
			patchSavePasswordEntries.Unpatch()
		}()

		err := savePasswordEntry(mockPasswordEntry)

		assert.NoError(t, err)
	})

	t.Run("Error while loading password entries", func(t *testing.T) {
		patchErrorLoadPasswordEntries := monkey.Patch(loadPasswordEntries, mockErrorLoadPasswordEntries)

		defer patchErrorLoadPasswordEntries.Unpatch()

		err := savePasswordEntry(mockPasswordEntry)

		assert.Error(t, err)
	})

	t.Run("Error while saving Password Entries", func(t *testing.T) {
		patchLoadPasswordEntries := monkey.Patch(loadPasswordEntries, mockLoadPasswordEntries)
		patchErrorSavePasswordEntries := monkey.Patch(savePasswordEntries, mockErrorSavePasswordEntries)

		defer func() {
			patchLoadPasswordEntries.Unpatch()
			patchErrorSavePasswordEntries.Unpatch()
		}()

		err := savePasswordEntry(mockPasswordEntry)

		assert.Error(t, err)
	})
}

// Test Save Password Entries method
func TestSavePasswordEntries(t *testing.T) {

	var mockNonce [24]byte
	_, _ = rand.Read(mockNonce[:])

	mockPasswordEntry := EncryptedPasswordEntry{
		Tag:      "TestTag",
		Cipher:   []byte("TestCipher"),
		Username: "TestUsername",
		Nonce:    mockNonce,
	}

	var mockPasswordEntries []EncryptedPasswordEntry

	mockPasswordEntries = append(mockPasswordEntries, mockPasswordEntry)

	mockwriteFile := func(name string, data []byte, perm fs.FileMode) error {
		return nil
	}

	mockErrorWriteFile := func(name string, data []byte, perm fs.FileMode) error {
		return errors.New("Error while writing file")
	}

	mockErrorMarshal := func(v any, prefix string, indent string) ([]byte, error) {
		return nil, errors.New("Error while marshalling password entries")
	}

	t.Run("Successfully save password entries", func(t *testing.T) {
		patchWriteFile := monkey.Patch(os.WriteFile, mockwriteFile)

		defer patchWriteFile.Unpatch()

		err := savePasswordEntries(mockPasswordEntries)

		assert.NoError(t, err)
	})

	t.Run("Error while saving to file", func(t *testing.T) {
		patchErrorWriteFile := monkey.Patch(os.WriteFile, mockErrorWriteFile)

		defer patchErrorWriteFile.Unpatch()

		err := savePasswordEntries(mockPasswordEntries)

		assert.Error(t, err)
	})

	t.Run("Error while marshalling password entries", func(t *testing.T) {
		patchErrorMarshal := monkey.Patch(json.MarshalIndent, mockErrorMarshal)

		defer patchErrorMarshal.Unpatch()

		err := savePasswordEntries(mockPasswordEntries)

		assert.Error(t, err)
	})

}

// Test Load Password Entries method
func TestLoadPasswordEntries(t *testing.T) {

	mockReadFile := func(name string) ([]byte, error) {
		return []byte("File Content"), nil
	}

	mockMarshal := func(data []byte, v any) error {
		return nil
	}

	mockErrorMarshal := func(data []byte, v any) error {
		return errors.New("Error while Unmarshalling password entries")
	}

	mockErrorReadFile := func(name string) ([]byte, error) {
		return nil, errors.New("Error while reading file")
	}

	mockNoFile := func(name string) ([]byte, error) {

		return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
	}

	t.Run("Successfully load password entries", func(t *testing.T) {
		patchReadFile := monkey.Patch(os.ReadFile, mockReadFile)
		patchMarshal := monkey.Patch(json.Unmarshal, mockMarshal)

		defer func() {
			patchReadFile.Unpatch()
			patchMarshal.Unpatch()
		}()

		_, err := loadPasswordEntries()

		assert.NoError(t, err)
	})

	t.Run("Error while Unmarshalling password entries", func(t *testing.T) {
		patchReadFile := monkey.Patch(os.ReadFile, mockReadFile)
		patchErrorMarshal := monkey.Patch(json.Unmarshal, mockErrorMarshal)

		defer func() {
			patchReadFile.Unpatch()
			patchErrorMarshal.Unpatch()
		}()

		_, err := loadPasswordEntries()

		assert.Error(t, err)
	})

	t.Run("Error while reading password entries", func(t *testing.T) {
		patchErrorReadFile := monkey.Patch(os.ReadFile, mockErrorReadFile)

		defer patchErrorReadFile.Unpatch()

		_, err := loadPasswordEntries()

		assert.Error(t, err)
	})

	t.Run("File doesn't exist", func(t *testing.T) {
		patchNoFile := monkey.Patch(os.ReadFile, mockNoFile)

		defer patchNoFile.Unpatch()

		entries, err := loadPasswordEntries()

		assert.NoError(t, err)
		assert.Empty(t, entries)
	})
}

// Test Save Users method
func TestSaveUsers(t *testing.T) {

	mockUser := User{
		Username: "TestUsername",
		Password: "TestPassword",
	}

	var mockUsers []User

	mockUsers = append(mockUsers, mockUser)

	mockwriteFile := func(name string, data []byte, perm fs.FileMode) error {
		return nil
	}

	mockErrorWriteFile := func(name string, data []byte, perm fs.FileMode) error {
		return errors.New("Error while writing file")
	}

	mockErrorMarshal := func(v any, prefix string, indent string) ([]byte, error) {
		return nil, errors.New("Error while marshalling password entries")
	}

	t.Run("Successfully save users", func(t *testing.T) {
		patchWriteFile := monkey.Patch(os.WriteFile, mockwriteFile)

		defer patchWriteFile.Unpatch()

		err := saveUsers(mockUsers)

		assert.NoError(t, err)
	})

	t.Run("Error while marshalling user records", func(t *testing.T) {
		patchErrorMarshal := monkey.Patch(json.MarshalIndent, mockErrorMarshal)

		defer patchErrorMarshal.Unpatch()

		err := saveUsers(mockUsers)

		assert.Error(t, err)
	})

	t.Run("Error while writing user records", func(t *testing.T) {
		patchErrorWriteFile := monkey.Patch(os.WriteFile, mockErrorWriteFile)

		defer patchErrorWriteFile.Unpatch()

		err := saveUsers(mockUsers)

		assert.Error(t, err)
	})
}

// Test Load Users method
func TestLoadUsers(t *testing.T) {
	mockReadFile := func(name string) ([]byte, error) {
		return []byte("File Content"), nil
	}

	mockMarshal := func(data []byte, v any) error {
		return nil
	}

	mockErrorMarshal := func(data []byte, v any) error {
		return errors.New("Error while Unmarshalling password entries")
	}

	mockErrorReadFile := func(name string) ([]byte, error) {
		return nil, errors.New("Error while reading file")
	}

	mockNoFile := func(name string) ([]byte, error) {

		return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrNotExist}
	}
	t.Run("Successfully load user entries", func(t *testing.T) {
		patchReadFile := monkey.Patch(os.ReadFile, mockReadFile)
		patchMarshal := monkey.Patch(json.Unmarshal, mockMarshal)

		defer func() {
			patchReadFile.Unpatch()
			patchMarshal.Unpatch()
		}()

		_, err := loadUsers()

		assert.NoError(t, err)
	})

	t.Run("Error while Unmarshalling user entries", func(t *testing.T) {
		patchReadFile := monkey.Patch(os.ReadFile, mockReadFile)
		patchErrorMarshal := monkey.Patch(json.Unmarshal, mockErrorMarshal)

		defer func() {
			patchReadFile.Unpatch()
			patchErrorMarshal.Unpatch()
		}()

		_, err := loadUsers()

		assert.Error(t, err)
	})

	t.Run("Error while reading user entries", func(t *testing.T) {
		patchErrorReadFile := monkey.Patch(os.ReadFile, mockErrorReadFile)

		defer patchErrorReadFile.Unpatch()

		_, err := loadUsers()

		assert.Error(t, err)
	})

	t.Run("File doesn't exist", func(t *testing.T) {
		patchNoFile := monkey.Patch(os.ReadFile, mockNoFile)

		defer patchNoFile.Unpatch()

		entries, err := loadUsers()

		assert.NoError(t, err)
		assert.Empty(t, entries)
	})

}
