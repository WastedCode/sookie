package sookie

import (
    "crypto/hmac"
    "crypto/sha256"
    "errors"
    "net/http"
    "github.com/wastedcode/crypter"
    "github.com/wastedcode/serializer"
)

var InvalidKey = errors.New("Invalid key. Please provide a string of length 16, 24 or 32.")
var HmacCheckFailure = errors.New("Invalid HMAC")

type SecureCookie struct {
    HttpCookie *http.Cookie
    Key string
    Value interface{}
}

// Generates a new Secure Cookie from the given data
// The http cookie contains the encrypted and encoded value
func NewSecureCookieFromData(key string, value interface{}) (*SecureCookie, error) {
    // Check if the encryption key is valid
    if (isValidCryptKey(key) == false) { return nil, InvalidKey }

    secureCookie := SecureCookie {
        HttpCookie: &http.Cookie{},
        Key: key,
        Value: value,
    }

    // Encrypt the given data and store it in the http cookie
    err := secureCookie.Encrypt()
    if (err != nil) { return nil, err }

    return &secureCookie, nil
}

// Given an http cookie, it will try to decode/decrypt it
// The value will be stored in the interface, and an empty
// SecureCookie object will be returned
// SecureCookie.Value is not set, but the value interface given is
func DecodeHttpCookie(key string, cookie *http.Cookie, value interface{}) (*SecureCookie, error) {
    // Check if the encryption key is valid
    if (isValidCryptKey(key) == false) {
        return nil, InvalidKey
    }

    secureCookie := SecureCookie {
        HttpCookie: cookie,
        Key: key,
    }

    // Does not update the Value of secureCookie
    err := secureCookie.Decrypt(value)
    if (err != nil) { return nil, err }

    return &secureCookie, nil
}

// Encrypt the contents from Value into the http cookie
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
    secureCookie.HttpCookie.Value = serializer.ByteToBase64String(
        AppendMAC(crypt.CipherData, secureCookie.Key))
    return nil
}

// Decrypt the value from the HttpCookie
// Returns nil for success
func (secureCookie *SecureCookie) Decrypt(value interface{}) error {
    // We get the raw bytes from the base64 encoded string
    decoded, err := serializer.Base64StringToByte(secureCookie.HttpCookie.Value)
    if (err != nil) { return err }

    // Try to extract the data and signature from the payload
    data, expectedMac, err := GetDataAndMac(decoded, secureCookie.Key)
    if (err != nil) { return err }

    // Make sure the Hmac matches the data
    if (!CheckMac(data, expectedMac, secureCookie.Key)) { return HmacCheckFailure }

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

// Given raw data, appends its hmac signature at the end
func AppendMAC(data []byte, key string) []byte {
    mac := hmac.New(sha256.New, []byte(key))
    mac.Write(data)
    return mac.Sum(data)
}

// The hmac signature is fixed size, and appended at the end
func GetDataAndMac(input []byte, key string) (data []byte, messageMac []byte, err error) {
    mac := hmac.New(sha256.New, []byte(key))
    size := mac.Size()
    length := len(input) - size
    if (length < 0) { return nil, nil, HmacCheckFailure }
    return input[:length], input[length:], nil
}

// Compare the given mac for the data
func CheckMac(data []byte, expectedMac []byte, key string) bool {
    mac := hmac.New(sha256.New, []byte(key))
    mac.Write(data)
    calculatedMac := mac.Sum(nil)
    return hmac.Equal(calculatedMac, expectedMac)
}

// Check if the incoming encryption key is valid
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
