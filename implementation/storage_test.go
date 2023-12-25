package implementation

//Test Save Password Entry method
func TestSavePasswordEntry(t *testing.T){

	var mockNonce [24]byte
	_ := rand.Read(mockNonce[:])

	mockPasswordEntry := EncryptedPasswordEntry{
		Tag: "TestTag",
		Cipher: []byte("TestCipher"),
		Username: "TestUsername",
		Nonce: mockNonce
	}

	mockLoadPasswordEntries := func() ([]EncryptedPasswordEntry, error){
		return []EncryptedPasswordEntry{}, nil
	}

	mockErrorLoadPasswordEntries := func() ([]EncryptedPasswordEntry, error){
		return nil, errors.New("Error while loading password entries")
	}

	mockSavePasswordEntries := func(entries []EncryptedPasswordEntry) error{
		return nil
	}

	mockErrorSavePasswordEntries := func(entries []EncryptedPasswordEntry) error{
		return errors.New("Error while saving password entries")
	}

	t.Run("Successfully save password entry", func(t *testing.T){
		patchLoadPasswordEntries := monkey.Patch(loadPasswordEntries, mockLoadPasswordEntries)
		patchSavePasswordEntries := monkey.Patch(savePasswordEntries, mockSavePasswordEntries)

		defer func(){
			patchLoadPasswordEntries.Unpatch()
			patchSavePasswordEntries.Unpatch()
		}()

		err := savePasswordEntry(mockPasswordEntry)

		assert.NoError(t,err)
	})

	t.Run("Error while loading password entries", func(t *testing.T){
		patchErrorLoadPasswordEntries := monkey.Patch(loadPasswordEntries, mockErrorLoadPasswordEntries)

		defer patchErrorLoadPasswordEntries.Unpatch()

		err := savePasswordEntry(mockPasswordEntry)

		assert.Error(t,err)
	})

	t.Run("Error while saving Password Entries", func(t *testing.T){
		patchLoadPasswordEntries := monkey.Patch(loadPasswordEntries, mockLoadPasswordEntries)
		patchErrorSavePasswordEntries := monkey.Patch(savePasswordEntries, mockErrorSavePasswordEntries)

		defer func(){
			patchLoadPasswordEntries.Unpatch()
			patchErrorSavePasswordEntries.Unpatch()
		}()

		err := savePasswordEntry(mockPasswordEntry)

		assert.Error(t,err)
	})
}

//Test Save Password Entries method
func TestSavePasswordEntries(t *testing.T){

	var mockNonce [24]byte
	_ := rand.Read(mockNonce[:])

	mockPasswordEntry := EncryptedPasswordEntry{
		Tag: "TestTag",
		Cipher: []byte("TestCipher"),
		Username: "TestUsername",
		Nonce: mockNonce
	}

	mockwriteFile := func() error{
		return nil
	}

	mockErrorWriteFile := func() error{
		return errors.New("Error while writing file")
	}

	t.Run("Successfully save password entries", func(t *testing.T){
		patchWriteFile := monkey.Patch(os.WriteFile, mockwriteFile)

		defer patchWriteFile.Unpatch()

		err := savePasswordEntries([]mockPasswordEntry)

		assert.NoError(t, err)
	})


}