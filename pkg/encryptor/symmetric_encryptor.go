package encryptor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"errors"
)

func AesEncrypt(data string, key string) (string, error) {
	iv, err := GenerateRandomString(16)
	if err != nil {
		return "", err
	}

	encrypted, err := basicEncrypt(data, key, iv)
	if err != nil {
		return "", err
	}

	encryptedMap := []string{encrypted, iv}
	str, err := json.Marshal(encryptedMap)
	if err != nil {
		return "", err
	}

	encoded := base64.StdEncoding.EncodeToString(str)
	return encoded, nil
}

func AesDecrypt(encryptedData string, key string) (string, error) {
	encrypted, err := base64.StdEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}

	var data []string
	json.Unmarshal(encrypted, &data)

	encryptedString := data[0]
	iv := data[1]

	decrypted, _ := basicDecrypt(encryptedString, key, iv)

	return decrypted, nil
}

func basicEncrypt(plainText string, key string, iv string) (string, error) {
	// create block using key
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	// create plaintextblock
	var plainTextBlock []byte
	plainTextLength := len(plainText)
	extendBlock := aes.BlockSize - (plainTextLength % aes.BlockSize)
	extendBytes := bytes.Repeat([]byte{uint8(extendBlock)}, extendBlock)

	plainTextBlock = make([]byte, plainTextLength+extendBlock)
	copy(plainTextBlock[plainTextLength:], extendBytes)
	copy(plainTextBlock, plainText)

	// create ciphertext with plaintextblock
	cipherText := make([]byte, len(plainTextBlock))

	// create encryptor using block and iv
	mode := cipher.NewCBCEncrypter(block, []byte(iv))

	// encrypt data
	mode.CryptBlocks(cipherText, plainTextBlock)
	str := base64.StdEncoding.EncodeToString(cipherText)
	return str, nil
}

func basicDecrypt(encrypted string, key string, iv string) (string, error) {
	// get cipher text from encrypted data
	cipherText, err := base64.StdEncoding.DecodeString(encrypted)
	if err != nil {
		return "", err
	}

	// create block using key
	block, err := aes.NewCipher([]byte(key))
	if err != nil {
		return "", err
	}

	if len(cipherText)%aes.BlockSize != 0 {
		return "", errors.New("block size cant be zero")
	}

	// create decryptor using block and iv
	mode := cipher.NewCBCDecrypter(block, []byte(iv))

	// decrypt data
	mode.CryptBlocks(cipherText, cipherText)
	cipherTextLength := len(cipherText)
	cipherText = cipherText[:(cipherTextLength - int(cipherText[cipherTextLength-1]))]

	return string(cipherText), nil
}
