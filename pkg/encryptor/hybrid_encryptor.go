package encryptor

import (
	"encoding/json"
)

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
