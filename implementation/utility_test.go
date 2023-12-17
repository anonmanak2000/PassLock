package implementation

import (
	"crypto/rand"
	"fmt"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/crypto/bcrypt"
)

// Test ReadUsername Function
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

// Test ReadPassword Function
// MockTermReader is a mock implementation of the TermReader interface.
type MockTermReader struct {
	mock.Mock
}

// ReadPassword is the mocked method for TermReader.ReadPassword.
func (m *MockTermReader) ReadPassword(fd int) ([]byte, error) {
	args := m.Called(fd)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).([]byte), args.Error(1)
}
func TestReadPassword(t *testing.T) {
	t.Run("Successful password input", func(t *testing.T) {

		mockReader := new(MockTermReader)
		expectedPassword := "test_password"
		mockReader.On("ReadPassword", mock.Anything).Return([]byte(expectedPassword), nil)

		result, err := readPassword(mockReader)

		assert.NoError(t, err)
		assert.Equal(t, expectedPassword, result)

		mockReader.AssertExpectations(t)
	})

	t.Run("Error during password input", func(t *testing.T) {

		mockReader := new(MockTermReader)
		expectedError := fmt.Errorf("error reading password")
		mockReader.On("ReadPassword", mock.Anything).Return(nil, expectedError)

		result, err := readPassword(mockReader)

		assert.Error(t, err)
		assert.Empty(t, result)
		mockReader.AssertExpectations(t)
	})
}

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
		// Arrange
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

// Test HashPassword Function
func TestHashPassword(t *testing.T) {
	t.Run("Successfully Hash Password", func(t *testing.T) {
		mockPassword := "MockPassword"
		hashedPassword, err := hashPassword(mockPassword)

		assert.NoError(t, err)
		assert.NotEmpty(t, hashedPassword)
		assert.True(t, bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(mockPassword)) == nil, "Hashed Password and mock password donot match")
	})
}
