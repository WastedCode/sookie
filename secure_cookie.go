// Package sookie is a way to generate a secure Http Cookie
// The value of the cookie is an encrypted and signed data
// The SecureCookie, serializes, encryptes, and signs the data
// And stores it in the cookie
// Example Usage:
//    type testingInterface struct {
//        Number int
//        OtherInfo string
//    }

//    testData := testingInterface{ 10, "info"}
//    secureCookie, err := NewSecureCookieFromData(key, testData)
//    secureCookie.HttpCookie // has the http cookie with encrypted contents

//    decryptedValue := testingInterface{}
//    // Decode the Cookie from above into decryptedValue
//    _, err = DecodeHttpCookie(key, secureCookie.HttpCookie, &decryptedValue)
package sookie

import (
    "crypto/hmac"
    "crypto/sha256"
    "errors"
    "net/http"
    "github.com/wastedcode/crypter"
    "github.com/wastedcode/serializer"
)

// Error raised when the key is incorrect length
var ErrInvalidKey = errors.New("invalid key, please provide a string of length 16, 24 or 32")
// Error raised when the HMAC check fails
var ErrHmacCheckFailure = errors.New("invalid HMAC")

// SecureCookie is a wrapper around a regular HTTP cookie
// It contains the raw value that was encrypted into the cookie
// And also the key used to encrypt/hash
type SecureCookie struct {
    HTTPCookie *http.Cookie
    Key string
    Value interface{}
}

// NewSecureCookieFromData generates a new Secure Cookie from the given data
// The http cookie contains the encrypted and encoded value
func NewSecureCookieFromData(key string, value interface{}) (*SecureCookie, error) {
    // Check if the encryption key is valid
    if (isValidCryptKey(key) == false) { return nil, ErrInvalidKey }

    secureCookie := SecureCookie {
        HTTPCookie: &http.Cookie{},
        Key: key,
        Value: value,
    }

    // Encrypt the given data and store it in the http cookie
    err := secureCookie.Encrypt()
    if (err != nil) { return nil, err }

    return &secureCookie, nil
}

// DecodeHTTPCookie decode/decrypts the given http cookie
// The value will be stored in the interface, and an empty
// SecureCookie object will be returned
// SecureCookie.Value is not set, but the value interface given is
func DecodeHTTPCookie(key string, cookie *http.Cookie, value interface{}) (*SecureCookie, error) {
    // Check if the encryption key is valid
    if (isValidCryptKey(key) == false) {
        return nil, ErrInvalidKey
    }

    secureCookie := SecureCookie {
        HTTPCookie: cookie,
        Key: key,
    }

    // Does not update the Value of secureCookie
    err := secureCookie.Decrypt(value)
    if (err != nil) { return nil, err }

    return &secureCookie, nil
}

// Encrypt will encrypt the contents from Value into the http cookie
// Returns nil for success
func (secureCookie *SecureCookie) Encrypt() (error) {
    // Try to serialize the data to string
    // This should first encode it in Gob, and then base64 the bytes
    serializedValue, err := serializer.SerializeInterfaceToString(secureCookie.Value)
    if (err != nil) { return err }

    // The encoded data is then encrypted
    crypt, err := crypter.NewCryptFromUnencryptedData([]byte(serializedValue), secureCookie.Key)
    if (err != nil) { return err }
    _, err = crypt.Encrypt()
    if (err != nil) { return err }

    // The encrypted data is signed and the hmac signature appended to the data
    // The two are then encoded using Base64
    secureCookie.HTTPCookie.Value = serializer.ByteToBase64String(
        AppendMAC(crypt.CipherData, secureCookie.Key))
    return nil
}

// Decrypt will decrypt the value from the HTTPCookie in the given interface
// Returns nil for success
func (secureCookie *SecureCookie) Decrypt(value interface{}) error {
    // We get the raw bytes from the base64 encoded string
    decoded, err := serializer.Base64StringToByte(secureCookie.HTTPCookie.Value)
    if (err != nil) { return err }

    // Try to extract the data and signature from the payload
    data, expectedMac, err := GetDataAndMac(decoded, secureCookie.Key)
    if (err != nil) { return err }

    // Make sure the Hmac matches the data
    if (!CheckMac(data, expectedMac, secureCookie.Key)) { return ErrHmacCheckFailure }

    // Attempt to decrypt the data
    crypt, err := crypter.NewCryptFromCipherData(data, secureCookie.Key)
    if (err != nil) { return err }
    _, err = crypt.Decrypt()
    if (err != nil) { return err }

    // Deserialize the encrypted data into the interface
    err = serializer.DeserializeStringToInterface(string(crypt.UnencryptedData), value)
    if (err != nil) { return err }

    return nil
}

// AppendMAC appends the hmac signature of the data
// at the end of the data given
func AppendMAC(data []byte, key string) []byte {
    mac := hmac.New(sha256.New, []byte(key))
    mac.Write(data)
    return mac.Sum(data)
}

// GetDataAndMac extracts the data and mac out of a blob of data
// The hmac signature is fixed size, and appended at the end
func GetDataAndMac(input []byte, key string) (data []byte, messageMac []byte, err error) {
    mac := hmac.New(sha256.New, []byte(key))
    size := mac.Size()
    length := len(input) - size
    if (length < 0) { return nil, nil, ErrHmacCheckFailure }
    return input[:length], input[length:], nil
}

// CheckMac will attempt to check the HMAC signature
func CheckMac(data []byte, expectedMac []byte, key string) bool {
    mac := hmac.New(sha256.New, []byte(key))
    mac.Write(data)
    calculatedMac := mac.Sum(nil)
    return hmac.Equal(calculatedMac, expectedMac)
}

// isValidCryptKey checks if the incoming encryption key is valid
func isValidCryptKey(key string) (isValid bool) {
    defer func() {
        if (recover() != nil) {
            // ValidateCryptKey paniced
            isValid = false
        }
    }()
    crypter.ValidateCryptKey(key)
    return true
}
