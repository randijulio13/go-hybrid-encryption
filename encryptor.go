package encryptor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
)

func GenerateRandomString(length int) (string, error) {
	// Hitung jumlah byte yang diperlukan untuk panjang string yang diinginkan
	byteLength := (length * 3) / 4 // Konversi panjang string ke panjang base64

	// Buat slice untuk menampung byte acak
	randomBytes := make([]byte, byteLength)

	// Baca byte acak dari crypto/rand
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	}

	// Konversi byte menjadi string base64
	randomString := base64.URLEncoding.EncodeToString(randomBytes)

	// Potong string menjadi panjang yang diinginkan
	return randomString[:length], nil
}

func GenerateKeypair() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		panic(err)
	}

	publicKey := &privateKey.PublicKey

	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		panic(err)
	}
	privateKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: privateKeyBytes,
	})
	err = os.WriteFile("private.key", privateKeyPEM, 0644)
	if err != nil {
		panic(err)
	}

	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		panic(err)
	}
	publicKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: publicKeyBytes,
	})
	err = os.WriteFile("public.key", publicKeyPEM, 0644)
	if err != nil {
		panic(err)
	}
}

func PublicEncrypt(plainText string, publicKeyPEM string) (string, error) {
	// Decode kunci publik dari format PEM
	publicKeyBlock, _ := pem.Decode([]byte(publicKeyPEM))
	if publicKeyBlock == nil || publicKeyBlock.Type != "PUBLIC KEY" {
		return "", errors.New("failed to decode PEM public key")
	}

	// Parse kunci publik X.509
	key, err := x509.ParsePKIXPublicKey(publicKeyBlock.Bytes)
	if err != nil {
		return "", err
	}

	// Cast kunci publik menjadi *rsa.PublicKey
	rsaPublicKey := key.(*rsa.PublicKey)

	// Enkripsi teks menggunakan kunci publik
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, rsaPublicKey, []byte(plainText))
	if err != nil {
		return "", err
	}

	encoded := base64.StdEncoding.EncodeToString(ciphertext)
	return encoded, nil
}

func PrivateDecrypt(data string, privateKeyPEM string) (string, error) {
	encryptedData, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return "", err
	}

	privateKeyBlock, _ := pem.Decode([]byte(privateKeyPEM))
	if privateKeyBlock == nil || privateKeyBlock.Type != "PRIVATE KEY" {
		return "", errors.New("failed to decode PEM private key")
	}
	privateKey, err := x509.ParsePKCS8PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return "", err
	}

	ciphertext := []byte(encryptedData)
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey.(*rsa.PrivateKey), ciphertext)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func HybridEncrypt(plainText string, publicKey string) (string, error) {

	key, err := GenerateRandomString(32)
	if err != nil {
		return "", err
	}

	encryptedData, err := AesEncrypt(plainText, key)
	if err != nil {
		return "", err
	}

	encryptedKey, err := PublicEncrypt(key, publicKey)
	if err != nil {
		return "", err
	}

	data := make(map[string]string)
	data["key"] = encryptedKey
	data["content"] = encryptedData

	encoded, err := json.Marshal(&data)
	if err != nil {
		return "", err
	}

	return string(encoded), nil
}

func HybridDecrypt(encryptedData string, privateKey string) (string, error) {
	var decoded map[string]string
	json.Unmarshal([]byte(encryptedData), &decoded)

	key, err := PrivateDecrypt(decoded["key"], privateKey)
	if err != nil {
		return "", err
	}

	decryptedData, err := AesDecrypt(decoded["content"], key)
	if err != nil {
		return "", err
	}

	return decryptedData, nil
}

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
