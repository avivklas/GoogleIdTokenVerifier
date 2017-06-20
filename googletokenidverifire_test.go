package GoogleIdTokenVerifier

import "testing"

func TestCheckToken(t *testing.T) {
	authToken := "XXXXXXXXXXX.XXXXXXXXXXXX.XXXXXXXXXX"
	aud := "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX.apps.googleusercontent.com"
	actual, err := Verify(authToken, aud)
	if err != nil {
		t.Error(err)
	}
	var token *TokenInfo
	expected := token
	if actual != expected {
		t.Errorf("got %v\nwant %v", actual, expected)
	}
}
