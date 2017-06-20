package GoogleIdTokenVerifier

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"io/ioutil"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Certs is
type Certs struct {
	Keys []keys `json:"keys"`
}

type keys struct {
	Kty string `json:"kty"`
	Alg string `json:"alg"`
	Use string `json:"use"`
	Kid string `json:"Kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// TokenInfo is
type TokenInfo struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	AtHash        string `json:"at_hash"`
	Aud           string `json:"aud"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	GivenName     string `json:"given_name"`
	FamilyName    string `json:"family_name"`
	Picture       string `json:"picture"`
	Local         string `json:"locale"`
	Iss           string `json:"iss"`
	Azp           string `json:"azp"`
	Iat           int64  `json:"iat"`
	Exp           int64  `json:"exp"`
}

// https://developers.google.com/identity/sign-in/web/backend-auth
// https://github.com/google/oauth2client/blob/master/oauth2client/crypt.py

// Verify is
func Verify(authToken string, aud string) (*TokenInfo, error) {
	return VerifyGoogleIDToken(authToken, GetCerts(GetCertsFromURL()), aud)
}

// VerifyGoogleIDToken is
func VerifyGoogleIDToken(authToken string, certs *Certs, aud string) (*TokenInfo, error) {
	header, payload, signature, messageToSign, err := divideAuthToken(authToken)
	if err != nil {
		err := errors.New("Token is not valid, parsing failed")
		return nil, err
	}

	tokeninfo, err := getTokenInfo(payload)
	if err != nil {
		err := errors.New("Token is not valid, failed to parse")
		return tokeninfo, err
	}

	if aud != tokeninfo.Aud {
		err := errors.New("Token is not valid, Audience from token and certificate don't match")
		return tokeninfo, err
	}
	if (tokeninfo.Iss != "accounts.google.com") && (tokeninfo.Iss != "https://accounts.google.com") {
		err := errors.New("Token is not valid, ISS from token and certificate don't match")
		return tokeninfo, err
	}
	if !checkTime(tokeninfo) {
		err := errors.New("Token is not valid, Token is expired.")
		return tokeninfo, err
	}

	key, err := choiceKeyByKeyID(certs.Keys, getAuthTokenKeyID(header))
	if err != nil {
		return tokeninfo, err
	}
	n, err := urlsafeB64decode(key.N)
	if err != nil {
		return tokeninfo, err
	}
	e, err := urlsafeB64decode(key.E)
	if err != nil {
		return tokeninfo, err
	}
	pKey := rsa.PublicKey{N: byteToInt(n), E: btrToInt(byteToBtr(e))}
	err = rsa.VerifyPKCS1v15(&pKey, crypto.SHA256, messageToSign, signature)
	if err != nil {
		return tokeninfo, err
	}
	return tokeninfo, nil
}

func getTokenInfo(bt []byte) (*TokenInfo, error) {
	var a *TokenInfo
	err := json.Unmarshal(bt, &a)
	if err != nil {
		return nil, err
	}
	return a, nil
}

func checkTime(tokeninfo *TokenInfo) bool {
	if (time.Now().Unix() < tokeninfo.Iat) || (time.Now().Unix() > tokeninfo.Exp) {
		return false
	}
	return true
}

//GetCertsFromURL is
func GetCertsFromURL() []byte {
	res, _ := http.Get("https://www.googleapis.com/oauth2/v3/certs")
	certs, _ := ioutil.ReadAll(res.Body)
	res.Body.Close()
	return certs
}

//GetCerts is
func GetCerts(bt []byte) *Certs {
	var certs *Certs
	json.Unmarshal(bt, &certs)
	return certs
}

func urlsafeB64decode(str string) ([]byte, error) {
	if m := len(str) % 4; m != 0 {
		str += strings.Repeat("=", 4-m)
	}
	bt, err := base64.URLEncoding.DecodeString(str)
	if err != nil {
		return nil, err
	}
	return bt, nil
}

func choiceKeyByKeyID(a []keys, tknkid string) (keys, error) {

	for _, key := range a {
		if key.Kid == tknkid {
			return key, nil
		}

	}
	err := errors.New("Token is not valid, kid from token and certificate don't match")
	var b keys
	return b, err
}

func getAuthTokenKeyID(bt []byte) string {
	var a keys
	json.Unmarshal(bt, &a)
	return a.Kid
}

func divideAuthToken(str string) ([]byte, []byte, []byte, []byte, error) {
	args := strings.Split(str, ".")

	header, err := urlsafeB64decode(args[0])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	payload, err := urlsafeB64decode(args[1])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	signature, err := urlsafeB64decode(args[2])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	messageToSign, err := calcSum(args[0] + "." + args[1])
	if err != nil {
		return nil, nil, nil, nil, err
	}

	return header, payload, signature, messageToSign, nil
}

func byteToBtr(bt0 []byte) *bytes.Reader {
	var bt1 []byte
	if len(bt0) < 8 {
		bt1 = make([]byte, 8-len(bt0), 8)
		bt1 = append(bt1, bt0...)
	} else {
		bt1 = bt0
	}
	return bytes.NewReader(bt1)
}

func calcSum(str string) ([]byte, error) {
	a := sha256.New()
	_, err := a.Write([]byte(str))
	if err != nil {
		return nil, err
	}
	return a.Sum(nil), nil
}

func btrToInt(a io.Reader) int {
	var e uint64
	binary.Read(a, binary.BigEndian, &e)
	return int(e)
}

func byteToInt(bt []byte) *big.Int {
	a := big.NewInt(0)
	a.SetBytes(bt)
	return a
}
