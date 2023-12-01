package encryptor

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
)

func PublicEncrypt(plainText string, publicKeyPEM string) (string, error) {
	// Decode kunci publik dari format PEM
	publicKeyBlock, _ := pem.Decode([]byte(publicKeyPEM))
	if publicKeyBlock == nil || publicKeyBlock.Type != "RSA PUBLIC KEY" {
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
	if privateKeyBlock == nil || privateKeyBlock.Type != "RSA PRIVATE KEY" {
		return "", errors.New("failed to decode PEM private key")
	}
	privateKey, err := x509.ParsePKCS1PrivateKey(privateKeyBlock.Bytes)
	if err != nil {
		return "", err
	}

	ciphertext := []byte(encryptedData)
	plaintext, err := rsa.DecryptPKCS1v15(rand.Reader, privateKey, ciphertext)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
