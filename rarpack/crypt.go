package rarpack

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
)

// RAR5 file encryption ("-p" mode; headers stay readable):
//   - PBKDF2-HMAC-SHA256 key derivation with RAR's continuation quirk
//     (see UnRAR crypt5.cpp pbkdf2): the main 32-byte AES key is the
//     value after Count iterations; continuing the same chain 16 more
//     iterations yields the checksum HMAC key, 16 more the password
//     check value. Password bytes are the UTF-8 encoding.
//   - File data (the compressed stream) is AES-256-CBC encrypted with
//     a per-file random salt and IV, zero-padded to a 16-byte multiple.
//   - The header CRC32 is stored MAC-protected (ConvertHashToMAC) and
//     a 12-byte password check (8-byte XOR fold + 4-byte SHA-256
//     prefix) lets decoders reject wrong passwords immediately.

const (
	kdfLg2Count = 15 // 32768 iterations, RAR's default
	saltSize    = 16
)

// deriveKeys runs RAR5's PBKDF2 variant and returns the AES key, the
// checksum HMAC key, and the password check value (32 bytes each).
func deriveKeys(password string, salt []byte, count int) (key, hashKey, checkVal []byte) {
	pwd := []byte(password)
	prf := func(data []byte) []byte {
		h := hmac.New(sha256.New, pwd)
		h.Write(data)
		return h.Sum(nil)
	}
	sb := make([]byte, 0, len(salt)+4)
	sb = append(sb, salt...)
	sb = append(sb, 0, 0, 0, 1) // PBKDF2 block index 1, big-endian
	u := prf(sb)
	fn := append([]byte(nil), u...)
	outs := make([][]byte, 3)
	for i, n := range []int{count - 1, 16, 16} {
		for j := 0; j < n; j++ {
			u = prf(u)
			for k := range fn {
				fn[k] ^= u[k]
			}
		}
		outs[i] = append([]byte(nil), fn...)
	}
	return outs[0], outs[1], outs[2]
}

// passwordCheck folds the 32-byte check value into the 12-byte form
// stored in the encryption record.
func passwordCheck(checkVal []byte) []byte {
	fold := make([]byte, 8)
	for i, v := range checkVal {
		fold[i%8] ^= v
	}
	sum := sha256.Sum256(fold)
	return append(fold, sum[:4]...)
}

// macCRC32 converts a plain CRC32 into its password-protected form.
func macCRC32(crc uint32, hashKey []byte) uint32 {
	var raw [4]byte
	binary.LittleEndian.PutUint32(raw[:], crc)
	h := hmac.New(sha256.New, hashKey)
	h.Write(raw[:])
	d := h.Sum(nil)
	var out uint32
	for i, v := range d {
		out ^= uint32(v) << (uint(i%4) * 8)
	}
	return out
}

type fileCrypt struct {
	salt, iv     []byte
	key, hashKey []byte
	check        []byte // 12-byte stored form
	useMAC       bool   // store the header CRC32 MAC-protected
}

func newFileCrypt(password string) (*fileCrypt, error) {
	fc := &fileCrypt{salt: make([]byte, saltSize), iv: make([]byte, aes.BlockSize)}
	if _, err := rand.Read(fc.salt); err != nil {
		return nil, err
	}
	if _, err := rand.Read(fc.iv); err != nil {
		return nil, err
	}
	key, hashKey, checkVal := deriveKeys(password, fc.salt, 1<<kdfLg2Count)
	fc.key, fc.hashKey, fc.check = key, hashKey, passwordCheck(checkVal)
	fc.useMAC = true
	return fc, nil
}

// encrypt pads data with zeros to a block multiple and AES-CBC encrypts.
func (fc *fileCrypt) encrypt(data []byte) []byte {
	padded := make([]byte, (len(data)+aes.BlockSize-1)/aes.BlockSize*aes.BlockSize)
	copy(padded, data)
	block, _ := aes.NewCipher(fc.key)
	cipher.NewCBCEncrypter(block, fc.iv).CryptBlocks(padded, padded)
	return padded
}

// extraRecord builds the file-header encryption record (type 1),
// including its record-size prefix.
func (fc *fileCrypt) extraRecord() []byte {
	var rec bytes.Buffer
	rec.Write(vint(0))    // version
	flags := uint64(0x01) // password check present
	if fc.useMAC {
		flags |= 0x02 // use MAC for the stored checksum
	}
	rec.Write(vint(flags))
	rec.WriteByte(kdfLg2Count)
	rec.Write(fc.salt)
	rec.Write(fc.iv)
	rec.Write(fc.check)
	var out bytes.Buffer
	out.Write(vint(uint64(len(vint(1)) + rec.Len())))
	out.Write(vint(1)) // record type: encryption
	out.Write(rec.Bytes())
	return out.Bytes()
}

// archiveCrypt holds the archive-wide encryption state for header
// encryption ("-hp" mode). Mirroring WinRAR, all headers and all file
// data share one salt and key set; only IVs differ per header and per
// file. Stored CRC32s are plain (no MAC) in this mode.
type archiveCrypt struct {
	salt, key, check []byte
}

func newArchiveCrypt(password string) (*archiveCrypt, error) {
	ac := &archiveCrypt{salt: make([]byte, saltSize)}
	if _, err := rand.Read(ac.salt); err != nil {
		return nil, err
	}
	key, _, checkVal := deriveKeys(password, ac.salt, 1<<kdfLg2Count)
	ac.key, ac.check = key, passwordCheck(checkVal)
	return ac, nil
}

// fileCrypt returns a per-file context sharing the archive salt/key,
// with a fresh random IV.
func (ac *archiveCrypt) fileCrypt() (*fileCrypt, error) {
	fc := &fileCrypt{salt: ac.salt, key: ac.key, check: ac.check, iv: make([]byte, aes.BlockSize)}
	if _, err := rand.Read(fc.iv); err != nil {
		return nil, err
	}
	return fc, nil
}

// block builds the HEAD_CRYPT block that opens a header-encrypted
// archive (the only plaintext header).
func (ac *archiveCrypt) block() []byte {
	var body bytes.Buffer
	body.Write(vint(4)) // HEAD_CRYPT
	body.Write(vint(0)) // header flags
	body.Write(vint(0)) // version
	body.Write(vint(1)) // flags: password check present
	body.WriteByte(kdfLg2Count)
	body.Write(ac.salt)
	body.Write(ac.check)
	return header(body.Bytes())
}

// encryptUnit encrypts one header unit with a fresh random IV and
// returns IV || ciphertext (zero padding to a block multiple).
func (ac *archiveCrypt) encryptUnit(unit []byte) ([]byte, error) {
	iv := make([]byte, aes.BlockSize)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	padded := make([]byte, (len(unit)+aes.BlockSize-1)/aes.BlockSize*aes.BlockSize)
	copy(padded, unit)
	block, _ := aes.NewCipher(ac.key)
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(padded, padded)
	return append(iv, padded...), nil
}
