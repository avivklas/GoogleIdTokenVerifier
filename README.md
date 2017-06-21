# GoogleIdTokenVerifier
To validate an Google ID Token in Golang

Usage:

```
authToken := "XXXXXXXXXXX.XXXXXXXXXXXX.XXXXXXXXXX"

aud := "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.apps.googleusercontent.com"

tokenInfo, err := Verify(authToken, aud)

if err != nil {
    // handle error
}

fmt.Println(tokenInfo)

```
