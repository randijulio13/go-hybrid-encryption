package test

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
	"testing"

	encryptor "gitlab.com/randijulio13/go-hybrid-encryption"
)

func GetAESDecrypted(encrypted string) ([]byte, error) {
	key := "my32digitkey12345678901234567890"
	iv := "my16digitIvKey12"

	ciphertext, err := base64.StdEncoding.DecodeString(encrypted)

	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher([]byte(key))

	if err != nil {
		return nil, err
	}

	if len(ciphertext)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("block size cant be zero")
	}

	mode := cipher.NewCBCDecrypter(block, []byte(iv))
	mode.CryptBlocks(ciphertext, ciphertext)
	ciphertext = PKCS5UnPadding(ciphertext)

	return ciphertext, nil
}

// PKCS5UnPadding  pads a certain blob of data with necessary data to be used in AES block cipher
func PKCS5UnPadding(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])

	return src[:(length - unpadding)]
}

// GetAESEncrypted encrypts given text in AES 256 CBC
func GetAESEncrypted(plaintext string) (string, error) {
	key := "my32digitkey12345678901234567890"
	iv := "my16digitIvKey12"

	var plainTextBlock []byte
	length := len(plaintext)

	extendBlock := 16 - (length % 16)
	plainTextBlock = make([]byte, length+extendBlock)
	copy(plainTextBlock[length:], bytes.Repeat([]byte{uint8(extendBlock)}, extendBlock))
	copy(plainTextBlock, plaintext)

	block, err := aes.NewCipher([]byte(key))

	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, len(plainTextBlock))
	mode := cipher.NewCBCEncrypter(block, []byte(iv))
	mode.CryptBlocks(ciphertext, plainTextBlock)

	str := base64.StdEncoding.EncodeToString(ciphertext)

	return str, nil
}

func TestLength(t *testing.T) {
	extendBytes := bytes.Repeat([]byte{uint8(5)}, 4)
	fmt.Println(extendBytes)
}
func TestEnc(t *testing.T) {
	plainText := "Hello, World!"
	fmt.Println("This is an original:", plainText)

	encrypted, err := GetAESEncrypted(plainText)

	if err != nil {
		fmt.Println("Error during encryption", err)
	}

	fmt.Println("This is an encrypted:", encrypted)

	decrypted, err := GetAESDecrypted(encrypted)

	if err != nil {
		fmt.Println("Error during decryption", err)
	}
	fmt.Println("This is a decrypted:", string(decrypted))
}

func TestEncrypt(t *testing.T) {
	key, err := encryptor.GenerateRandomString(32)
	fmt.Println(key)
	if err != nil {
		panic(err)
	}

	encrypted, err := encryptor.AesEncrypt("Helo World!", key)
	if err != nil {
		panic(err)
	}

	decrypted, err := encryptor.AesDecrypt(encrypted, key)
	if err != nil {
		panic(err)
	}

	fmt.Println(encrypted)
	fmt.Println(decrypted)
}
