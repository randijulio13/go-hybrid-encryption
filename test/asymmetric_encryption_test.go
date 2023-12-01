package test

import (
	"fmt"
	"os"
	"testing"

	encryptor "github.com/randijulio13/go-hybrid-encryption"
)

func TestKeypair(t *testing.T) {
	encryptor.GenerateKeypair()
}

func TestPublicEncryption(t *testing.T) {
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
}

func TestPublicEncrypt(t *testing.T) {
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
}

func TestPrivateDecrypt(t *testing.T) {
	privateKey, err := os.ReadFile("private.key")
	if err != nil {
		panic(err)
	}

	encrypted := "VcNtT7phSAyThgcbUTHkGvcbbT2HsfnDM85T1/bx5EORITFlYo5c3D+LbekWLxCnAxtme7sZQ7cfbhP8dPzBw/Cv3CQ9wjaY30tB/RjrzRiteq5W68eEXPZIPtBvdRZm1gpt30eB4a9mr4na8x1eFzQW9TGTeAgiUI5OxH/wVwOElm+n1xtyhJzeaFAg5haZu3nvvDGOUwD9Udyn4pUj4kVke7a63TcOQo4bexmPphzaoUy5u0+0cbtUDwbH+l+zG5GEVrs2Pfb78mm5EjGwkkOHMhHDEK6bV+ccDiA7e5Ecnr4eOIvSP8CseN14V7DSTu19qX77dpKGs7mRE1ZhJCmFIWDkrjIiSS3uDAIBfSMsBBHwG7nCgu8wBDtaa/PTjvMko5f3RddVk2s/21Yy2M2IGdZdrnHG1LEQCXCCpEdwoXPYTkN8fLQzo4wOwm6CptH74M8/eNo/cjDP6oxIZ9dOORVt6o7QnNfF2iYeG7TH1AZEKw71vzwSAaGwZwYsb84Iu/rboOO5dSrfLaq2DKa8xytg9hz7KPspTRSSOjQaMRrhCA9yeEHMBqQzVEYalXHIauzc7yzBtSYTH+QRPES9/+qMLu1mE/8nCHqB/d/Ihd/9Cx2FGjB7cgH9uSdKgvpDOZM8+qiynT7Np/KQbeEkdXNoE3Ak+toWS9VBlbc="
	decrypted, err := encryptor.PrivateDecrypt(encrypted, string(privateKey))
	if err != nil {
		panic(err)
	}
	fmt.Println(decrypted)
}
