package c2

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
)

// AES-256-GCM envelope: each Listener has its own 32-byte key + each message has its own 12-byte nonce.
// Wire format (base64 text, easy to send in HTTP body / SSE directly):
//   base64( nonce(12) || ciphertext+tag )
// Design notes:
//   - GCM includes a 16-byte AEAD tag, providing integrity + confidentiality in one pass, no extra HMAC needed;
//   - nonce is generated via crypto/rand; 96-bit collision probability is extremely low within the key lifetime (< 2^-32 / 4B messages);
//   - key never leaves the server: randomly generated 32 bytes when the listener is created, hard-coded into the beacon at compile time.

// GenerateAESKey generates a random 32-byte AES-256 key and returns it as base64
func GenerateAESKey() (string, error) {
	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

// GenerateImplantToken generates a 32-byte token, base64-encoded (carried by the implant in an HTTP header for authentication)
func GenerateImplantToken() (string, error) {
	t := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, t); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(t), nil
}

// EncryptAESGCM encrypts arbitrary plaintext, returning base64(nonce||ct)
func EncryptAESGCM(keyB64 string, plaintext []byte) (string, error) {
	key, err := decodeKey(keyB64)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, plaintext, nil)
	out := append(nonce, ct...)
	return base64.StdEncoding.EncodeToString(out), nil
}

// DecryptAESGCM decrypts base64(nonce||ct), returning plaintext
func DecryptAESGCM(keyB64, encB64 string) ([]byte, error) {
	key, err := decodeKey(keyB64)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(encB64)
	if err != nil {
		return nil, errors.New("ciphertext base64 invalid")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize+16 { // at least nonce + tag
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := raw[:nonceSize], raw[nonceSize:]
	pt, err := gcm.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, errors.New("aead open failed (key mismatch or tampered)")
	}
	return pt, nil
}

// EncryptAESGCMWithAAD encrypts with additional authenticated data bound to context (e.g. session_id).
// Prevents cross-session replay: ciphertext from session A cannot be fed to session B.
func EncryptAESGCMWithAAD(keyB64 string, plaintext []byte, aad []byte) (string, error) {
	key, err := decodeKey(keyB64)
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ct := gcm.Seal(nil, nonce, plaintext, aad)
	out := append(nonce, ct...)
	return base64.StdEncoding.EncodeToString(out), nil
}

// DecryptAESGCMWithAAD decrypts with AAD verification.
func DecryptAESGCMWithAAD(keyB64, encB64 string, aad []byte) ([]byte, error) {
	key, err := decodeKey(keyB64)
	if err != nil {
		return nil, err
	}
	raw, err := base64.StdEncoding.DecodeString(encB64)
	if err != nil {
		return nil, errors.New("ciphertext base64 invalid")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(raw) < nonceSize+16 {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := raw[:nonceSize], raw[nonceSize:]
	pt, err := gcm.Open(nil, nonce, ct, aad)
	if err != nil {
		return nil, errors.New("aead open failed (key mismatch, tampered, or AAD mismatch)")
	}
	return pt, nil
}

func decodeKey(keyB64 string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(keyB64)
	if err != nil {
		return nil, errors.New("key base64 invalid")
	}
	if len(key) != 32 {
		return nil, errors.New("key must be 32 bytes (AES-256)")
	}
	return key, nil
}
