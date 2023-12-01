package encryptor

import (
	"crypto/rand"
	"encoding/base64"
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
