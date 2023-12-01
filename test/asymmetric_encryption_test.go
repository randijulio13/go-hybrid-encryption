package test

import (
	"fmt"
	"os"
	"testing"

	"gitlab.com/randijulio13/go-hybrid-encryption/pkg/encryptor"
)

func TestKeypair(t *testing.T) {
	encryptor.GenerateKeypair()
}

func TestPublicEncrypt(t *testing.T) {
	encryptor.GenerateKeypair()
	publicKey, err := os.ReadFile("public.key")
	if err != nil {
		panic(err)
	}

	plainText := "Hello World!"

	encrypted, err := encryptor.PublicEncrypt(plainText, string(publicKey))
	if err != nil {
		panic(err)
	}
	fmt.Println(encrypted)

	privateKey, err := os.ReadFile("private.key")
	if err != nil {
		panic(err)
	}
	decrypted, err := encryptor.PrivateDecrypt(encrypted, string(privateKey))
	if err != nil {
		panic(err)
	}
	fmt.Println(decrypted)
	os.Remove("private.key")
	os.Remove("public.key")
}
