package rarpack

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"testing"
)

// Golden vectors from UnRAR's own TestPBKDF2 (crypt5.cpp): the main
// key after Count iterations is plain PBKDF2-HMAC-SHA256 block 1.
func TestDeriveKeysGolden(t *testing.T) {
	cases := []struct {
		pass, salt string
		count      int
		keyHex     string
	}{
		{"password", "salt", 1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{"password", "salt", 4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"},
		{"just some long string pretending to be a password", "salt, salt, salt, a lot of salt", 65536, "080fa31d422db047839bce3a3bce4951e262b9ff762f57e9c47196ce4b6b6ebf"},
	}
	for _, c := range cases {
		key, hashKey, checkVal := deriveKeys(c.pass, []byte(c.salt), c.count)
		want, _ := hex.DecodeString(c.keyHex)
		if !bytes.Equal(key, want) {
			t.Fatalf("count %d: key %x, want %x", c.count, key, want)
		}
		if len(hashKey) != 32 || len(checkVal) != 32 {
			t.Fatal("supplementary values must be 32 bytes")
		}
		if len(passwordCheck(checkVal)) != 12 {
			t.Fatal("stored check must be 12 bytes")
		}
	}
}

func TestEncryptDecryptRoundTrip(t *testing.T) {
	fc, err := newFileCrypt("pässwörd-123")
	if err != nil {
		t.Fatal(err)
	}
	data := []byte("hello encrypted world, hello hello hello")
	enc := fc.encrypt(data)
	if len(enc)%16 != 0 || len(enc) < len(data) {
		t.Fatalf("ciphertext %d bytes, want padded multiple of 16", len(enc))
	}
	// Decrypt with a fresh derivation from the same salt.
	key, _, _ := deriveKeys("pässwörd-123", fc.salt, 1<<kdfLg2Count)
	if !bytes.Equal(key, fc.key) {
		t.Fatal("re-derived key differs")
	}
	dec := append([]byte(nil), enc...)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	cipher.NewCBCDecrypter(block, fc.iv).CryptBlocks(dec, dec)
	if !bytes.Equal(dec[:len(data)], data) {
		t.Fatal("decrypt mismatch")
	}
}
