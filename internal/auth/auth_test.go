package auth

import (
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestBcrypt(t *testing.T) {
	pwds := []string{
		"ATestPassword",
		"12345",
		"Passwordmoron",
		"Le3tG3Ek",
	}
	hashs := make(map[string]string)
	for _, pwd := range pwds {
		var err error
		hashs[pwd], err = HashPassword(pwd)
		if err != nil {
			t.Error("failed to has password")

		}
	}
	for _, pwd := range pwds {
		if err := CheckPasswordHash(pwd, hashs[pwd]); err != nil {
			t.Errorf("Expected passwords to match hash FAILED for: %s : %s -- ERROR: %s", pwd, hashs[pwd], err.Error())
		}
	}
	for i := 1; i < len(pwds); i++ {
		if err := CheckPasswordHash(pwds[i], hashs[pwds[i-1]]); err == nil {
			t.Error("Passwords matched where they should not have")
		}
	}
}

func TestJwt(t *testing.T) {
	userId := uuid.New()
	secretString := "MadDog"
	jwt, err := MakeJWT(userId, secretString, time.Second)
	if err != nil {
		t.Error("Couldn't create 1 second jwt")
	}

	// Test valid
	retId, err := ValidateJWT(jwt, secretString)
	if err != nil {
		t.Errorf("Validation failed: %s", err.Error())
	}
	if retId != userId {
		t.Errorf("%s did not match returned %s", userId.String(), retId.String())
	}

	// Test Invalid
	_, err = ValidateJWT(jwt, "InvalidString")
	if err == nil {
		t.Error("Validation passed with wrong secret")
	}

	// Test Expired
	time.Sleep(time.Second * 2)
	_, err = ValidateJWT(jwt, "InvalidString")
	if err == nil {
		t.Error("Validation passed after expiration")
	}
}

func TestGetBearerToken(t *testing.T) {
	fakeToken := "ThisIsAVeryFakeToken"
	bearerStrings := []string{
		"Bearer",
		"bearer",
		"BEARER",
		"  bearer",
		"  Bearer",
		" Bearer  ",
	}
	for _, bearer := range bearerStrings {
		header := http.Header{}
		header.Add("Authorization", bearer+" "+fakeToken)
		ret, err := GetBearerToken(header)
		if err != nil {
			t.Errorf("Error in GetBearerToken: %s", err.Error())
		}
		if ret != fakeToken {
			t.Errorf("%v does not match original %v", ret, fakeToken)
		}
	}
	header := http.Header{}
	header.Add("Authorization", bearerStrings[4]+" "+fakeToken+"    ")
	ret, err := GetBearerToken(header)
	if err != nil {
		t.Errorf("Error in GetBearerToken: %s", err.Error())
	}
	if ret != fakeToken {
		t.Errorf("%v does not match original %v", ret, fakeToken)
	}
}
