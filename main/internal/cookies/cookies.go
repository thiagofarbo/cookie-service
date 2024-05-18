package cookies

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

var (
	ErrValueTooLong = errors.New("cookie value too long")
	ErrInvalidValue = errors.New("invalid cookie value")
)

func WriteEncrypted(w http.ResponseWriter, cookie http.Cookie, secretSignature []byte) error {
	// Create a new AES cipher block from the secret key.

	block, err := aes.NewCipher(secretSignature)
	if err != nil {
		return err
	}

	// Wrap the cipher block in Galois Counter Mode.
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return err
	}

	// Create a unique nonce containing 12 random bytes.
	nonce := make([]byte, aesGCM.NonceSize())
	_, err = io.ReadFull(rand.Reader, nonce)
	if err != nil {
		return err
	}

	// Prepare the plaintext input for encryption. Because we want to
	// authenticate the cookie name as well as the value, we make this plaintext
	// in the format "{cookie name}:{cookie value}". We use the : character as a
	// separator because it is an invalid character for cookie names and
	// therefore shouldn't appear in them.

	plaintext := fmt.Sprintf("%s:%s", cookie.Name, cookie.Value)

	// Encrypt the data using aesGCM.Seal(). By passing the nonce as the first
	// parameter, the encrypted data will be appended to the nonce — meaning
	// that the returned encryptedValue variable will be in the format
	// "{nonce}{encrypted plaintext data}".
	encryptedValue := aesGCM.Seal(nonce, nonce, []byte(plaintext), nil)

	// Set the cookie value to the encryptedValue.
	cookie.Value = string(encryptedValue)

	return WriteCookie(w, cookie)
}

func ReadEncrypted(r *http.Request, cookieName string, secretSignature []byte) (string, error) {

	// Read the encrypted value from the cookie as normal.
	encryptedValue, err := ReadCookie(r, cookieName)
	if err != nil {
		return "", err
	}
	// Create a new AES cipher block from the secret key.
	block, err := aes.NewCipher(secretSignature)
	if err != nil {
		return "", err
	}

	// Wrap the cipher block in Galois Counter Mode.
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := aesGCM.NonceSize()

	// To avoid a potential 'index out of range' panic in the next step, we
	// check that the length of the encrypted value is at least the nonce
	// size.

	if len(encryptedValue) < nonceSize {
		return "", ErrInvalidValue
	}

	// Split apart the nonce from the actual encrypted data.
	nonce := encryptedValue[:nonceSize]
	cipherText := encryptedValue[nonceSize:]

	// Use aesGCM.Open() to decrypt and authenticate the data. If this fails,
	// return a ErrInvalidValue error.

	plaintext, err := aesGCM.Open(nil, []byte(nonce), []byte(cipherText), nil)
	if err != nil {
		return "", ErrInvalidValue
	}

	// The plaintext value is in the format "{cookie name}:{cookie value}". We
	// use strings.Cut() to split it on the first ":" character.

	expectedName, value, ok := strings.Cut(string(plaintext), ":")
	if !ok {
		return "", ErrInvalidValue
	}

	// Check that the cookie name is the expected one and hasn't been changed.
	if expectedName != cookieName {
		return "", ErrInvalidValue
	}

	return value, nil

}

func WriteSigned(w http.ResponseWriter, cookie http.Cookie, secretSignature []byte) error {

	mac := hmac.New(sha256.New, secretSignature)
	mac.Write([]byte(cookie.Name))
	mac.Write([]byte(cookie.Value))

	signature := mac.Sum(nil)

	cookie.Value = string(signature) + cookie.Value
	return WriteCookie(w, cookie)
}

func ReadSigned(r *http.Request, cookieName string, secretSignature []byte) (string, error) {

	// Read in the signed value from the cookie. This should be in the format
	signedValue, err := ReadCookie(r, cookieName)
	if err != nil {
		return "", err
	}

	if len(signedValue) < sha256.Size {
		return "", ErrInvalidValue
	}

	// Split apart the signature and original cookie value.
	signature := signedValue[:sha256.Size]
	value := signedValue[sha256.Size:]

	// Recalculate the HMAC signature of the cookie name and original value.
	mac := hmac.New(sha256.New, secretSignature)
	mac.Write([]byte(cookieName))
	mac.Write([]byte(value))

	expectedSignature := mac.Sum(nil)

	// Check that the recalculated signature matches the signature we received
	// in the cookie. If they match, we can be confident that the cookie name
	// and value haven't been edited by the client.

	if !hmac.Equal([]byte(signature), expectedSignature) {
		return "", ErrInvalidValue
	}

	//Return the original cookie value :)
	return value, nil

}

func WriteCookie(w http.ResponseWriter, cookie http.Cookie) error {
	// Encode the cookie value using base64.

	cookie.Value = base64.URLEncoding.EncodeToString([]byte(cookie.Value))

	// error if it's more than 4096 bytes.
	if len(cookie.String()) > 4096 {
		return ErrValueTooLong
	}
	http.SetCookie(w, &cookie)
	return nil
}

func ReadCookie(r *http.Request, cookieName string) (string, error) {

	cookie, err := r.Cookie(cookieName)

	if cookie == nil {
		return "", err
	}

	value, err := base64.URLEncoding.DecodeString(cookie.Value)
	if err != nil {
		return "", ErrInvalidValue
	}
	return string(value), nil
}
