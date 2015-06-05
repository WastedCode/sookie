package sookie

import (
    "net/http"
    "testing"
)

type testingInterface struct {
    Number int
    OtherInfo string
}

var key = "1234567890123456"

func TestNewSecureCookieFromDataWithInterface(t *testing.T) {
    testData := testingInterface{ 10, "info"}
    secureCookie, err := NewSecureCookieFromData(key, testData)
    if (err != nil) { t.Error("Failed to create secure cookie for a struct") }

    decryptedValue := testingInterface{}
    _, err = DecodeHTTPCookie(key, secureCookie.HTTPCookie, &decryptedValue)
    if (err != nil) { t.Error("Unable to decode secure cookie generated http cookie") }

    if (decryptedValue.Number != testData.Number || decryptedValue.OtherInfo != testData.OtherInfo) {
        t.Error("The decoded data is incorrect")
    }
}

func TestNewSecureCookieFromDataWithString(t *testing.T) {
    testData := "abcdef"
    secureCookie, err := NewSecureCookieFromData(key, testData)
    if (err != nil) { t.Error("Failed to create secure cookie for a struct") }

    decryptedValue := ""
    _, err = DecodeHTTPCookie(key, secureCookie.HTTPCookie, &decryptedValue)
    if (err != nil) { t.Error("Unable to decode secure cookie generated http cookie") }

    if (decryptedValue != testData) {
        t.Error("The decoded data is incorrect")
    }
}

func TestNewSecureCookieWithBadKey(t *testing.T) {
    secureCookie, err := NewSecureCookieFromData("abcd", "some string")
    if (err == nil || secureCookie != nil) {
        t.Error("Expected an error when a bad key was given")
    }
}

func TestDecodeHTTPCookie(t *testing.T) {
    testData := testingInterface{ 10, "info"}
    secureCookie, err := NewSecureCookieFromData(key, testData)
    if (err != nil) { t.Error("Failed to create secure cookie for a struct") }

    decryptedValue := testingInterface{}
    decoded, err := DecodeHTTPCookie("abcded", secureCookie.HTTPCookie, &decryptedValue)

    if (err == nil || decoded != nil) {
        t.Error("Expected an error when a bad key was given")
    }
}

func TestDecodeHTTPCookieInvalidData(t *testing.T) {
    decryptedValue := testingInterface{}
    cookie := http.Cookie { Value: "blah"}
    decoded, err := DecodeHTTPCookie(key, &cookie, &decryptedValue)
    if (err == nil || decoded != nil) {
        t.Error("Expected an error when a bad key was given")
    }
}
