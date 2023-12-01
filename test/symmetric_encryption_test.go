package test

import (
	"fmt"
	"testing"

	encryptor "github.com/randijulio13/go-hybrid-encryption"
)

func TestAesEncryption(t *testing.T) {
	key, err := encryptor.GenerateRandomString(32)
	if err != nil {
		panic(err)
	}

	encrypted, err := encryptor.AesEncrypt("Helo World!", key)
	if err != nil {
		panic(err)
	}
	fmt.Println(encrypted)

	decrypted, err := encryptor.AesDecrypt(encrypted, key)
	if err != nil {
		panic(err)
	}
	fmt.Println(decrypted)
}

func TestAesEncrypt(t *testing.T) {
	key, err := encryptor.GenerateRandomString(32)
	fmt.Println(key)
	if err != nil {
		panic(err)
	}

	encrypted, err := encryptor.AesEncrypt("Helo World!", key)
	if err != nil {
		panic(err)
	}
	fmt.Println(encrypted)
}

func TestAesDecrypt(t *testing.T) {
	key := "ydtOE_hCFuHgraekpFEVhGsPI_5bIezy"
	encrypted := "WyJkU2hIblRlSWZkbnFQcHFycGJOSW5BPT0iLCI1WXJjRnRhVnd5OXRrUUtEIl0="
	decrypted, err := encryptor.AesDecrypt(encrypted, key)
	if err != nil {
		panic(err)
	}
	fmt.Println(decrypted)
}
