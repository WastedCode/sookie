# SecureCookie
Secure cookies in GoLang

[![Build Status](https://travis-ci.org/WastedCode/sookie.svg)](https://travis-ci.org/WastedCode/sookie) [![GoDoc](https://godoc.org/github.com/WastedCode/sookie?status.svg)](https://godoc.org/github.com/WastedCode/sookie)

## What's a Sookie?
Sookie lets you create Http Cookies where the data stored is serialized, encrypted and signed.
Similarly it allows you to decode Http Cookies with such data.

## Example Usage
```
type testingInterface struct {
    Number int
    OtherInfo string
}

testData := testingInterface{ 10, "info"}
secureCookie, err := NewSecureCookieFromData(key, testData)
secureCookie.HttpCookie // has the http cookie with encrypted contents

decryptedValue := testingInterface{}
// Decode the Cookie from above into decryptedValue
_, err = DecodeHttpCookie(key, secureCookie.HttpCookie, &decryptedValue)
```


