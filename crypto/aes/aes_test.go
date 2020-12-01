package aes

import (
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncrypt(t *testing.T) {
	var key = "1ae8ccd0e7985cc0b6203a55855a1034afc252980e970ca90e5202689f947ab9"
	var iv = "d58ce954203b7c9a9a9d467f59839249"

	keyByteAry, _ := hex.DecodeString(key)
	ivByteAry, _ := hex.DecodeString(iv)

	plainText := []byte("1234567812345678")
	crypted, err := Encrypt(keyByteAry, ivByteAry, plainText)
	enText := base64.StdEncoding.EncodeToString(crypted)
	assert.NoError(t, err)
	assert.Equal(t, "aAXtX48Ri2avZgYrJZ2ybA==", enText)

	plainText = []byte("123456781234567")
	crypted, err = Encrypt(keyByteAry, ivByteAry, plainText)
	enText = base64.StdEncoding.EncodeToString(crypted)
	assert.Error(t, err)
}

func TestEncryptPadded(t *testing.T) {
	var key = "1ae8ccd0e7985cc0b6203a55855a1034afc252980e970ca90e5202689f947ab9"
	var iv = "d58ce954203b7c9a9a9d467f59839249"

	keyByteAry, _ := hex.DecodeString(key)
	ivByteAry, _ := hex.DecodeString(iv)
	plainText := []byte("ABCDEFG")

	crypted, err := EncryptPadded(keyByteAry, ivByteAry, plainText)

	enText := base64.StdEncoding.EncodeToString(crypted)
	assert.NoError(t, err)
	assert.Equal(t, "3iIEkNQUcSar6WP8QnW1Sg==", enText)
}

func TestDecrypt(t *testing.T) {
	var key = "1ae8ccd0e7985cc0b6203a55855a1034afc252980e970ca90e5202689f947ab9"
	var iv = "d58ce954203b7c9a9a9d467f59839249"

	keyByteAry, _ := hex.DecodeString(key)
	ivByteAry, _ := hex.DecodeString(iv)

	enBase64Str := "3iIEkNQUcSar6WP8QnW1Sg=="

	en, err := base64.StdEncoding.DecodeString(enBase64Str)
	assert.NoError(t, err)

	plainText, err := Decrypt(keyByteAry, ivByteAry, en)

	assert.NoError(t, err)
	assert.Equal(t, "ABCDEFG", strings.TrimSpace(string(plainText)))
}
