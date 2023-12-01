package test

import (
	"fmt"
	"os"
	"testing"

	"gitlab.com/randijulio13/go-hybrid-encryption/pkg/encryptor"
)

func TestHybridEncryption(t *testing.T) {
	publicKey, err := os.ReadFile("public.key")
	if err != nil {
		panic(err)
	}
	plainText := "Hello World"
	encrypted, err := encryptor.HybridEncrypt(plainText, string(publicKey))
	if err != nil {
		panic(err)
	}
	fmt.Println(encrypted)

	privateKey, err := os.ReadFile("private.key")
	if err != nil {
		panic(err)
	}
	decrypted, err := encryptor.HybridDecrypt(encrypted, string(privateKey))
	if err != nil {
		panic(err)
	}
	fmt.Println(decrypted)
}

func TestHybridDecrypt(t *testing.T) {
	encrypted := `{"key":"mlOV0gHn8tyGhuk9uNzZaGIpmiEQsYCscWq0eWXxfUXQpx3sssHqlePwDos\/rvxjQ8Tm++TfFjXBeO0d4A\/ipjNT0rzO6LrQQbfCK5r6PAgKbYJIisACXAoH55EnnoizI3RAh19MYOi9FtjPCpW+vClNBmKqSlwqP\/6iYpD9\/npCb5sLvjJFzjCW3yY8WoQeJVuEgygT3X6P2s+tqc1Avgn\/5yzKnYt2y8zHNDGTCiFWmt2D76qscfylL7ulDwZZTAxKHW9GIEYMlxKJc2SdhgCL4TI9oI4g3i2mqoAyh5Zww\/fi0ybPI2HgtmhpNHrztKgNgBCvjm7Fv7TURuY2XDCY9Z7Hf\/pienszF7waieYxepa5OGOMQEpDmvya6qAD\/6hYWuuLE81C4yk9PdapqOmVeXTwsgd35BDs99vvR\/Ek2u2699BmHe1qAht4\/SDkDLLSuX8P4E\/GNiRSLAhRVMjZjw746UxQLTHszVDkYrO\/M2MacmLY9ueEGvnkdmv++6SVvtoirbvbrIwti0t9OnhluQ4nIuJDap2Ul4tsHXR5PizD89C1gkKvWloqN9uh+wdZXjp+lvvFFSrtcWd+kK7QsDG+oOh5qf5aSditp\/AZSDA55l29rec0Z9eb\/y43U73mXs07nih0lzI97FaAn\/0nYKh9637oCGdFqvcJG6g=","content":"WyJqWThscUVCaWlVWkRXcVRaWGgxQzV3PT0iLCJlZTdFRXV4OXppaVRvbnlPIl0="}`
	privateKey, err := os.ReadFile("private.key")
	if err != nil {
		panic(err)
	}
	decrypted, err := encryptor.HybridDecrypt(encrypted, string(privateKey))
	if err != nil {
		panic(err)
	}

	fmt.Println(decrypted)
}

func TestHybridEncrypt(t *testing.T) {
	publicKey, err := os.ReadFile("public.key")
	if err != nil {
		panic(err)
	}

	plainText := "Hello World"
	encrypted, err := encryptor.HybridEncrypt(plainText, string(publicKey))
	if err != nil {
		panic(err)
	}
	fmt.Println(encrypted)
}
