package server

import (
	"log"
	"crypto/rsa"
	"os"
	"io/ioutil"
	"time"
	"errors"
	jwt "github.com/dgrijalva/jwt-go"
)

var rsaJWTPriv *rsa.PrivateKey
var rsaJWTPub *rsa.PublicKey
var jwtSigningMethod = jwt.GetSigningMethod("RS256")

func openAndParseKey(jwt_key_file string) {
	if jwtPrivKey, err := os.Open(jwt_key_file); err == nil {
		defer jwtPrivKey.Close()
		if data, err := ioutil.ReadAll(jwtPrivKey); err == nil {
			if rsaJWTPriv, err = jwt.ParseRSAPrivateKeyFromPEM(data); err != nil {
				log.Println(err)
				panic("AD auth enabled but can't read JWT Private key!")
			}
		} else {
			log.Println(err)
			panic("AD auth enabled but can't read JWT Private key!")
		}
	} else {
		log.Println(err)
		panic("AD auth enabled but can't read JWT Private key!")
	}

	if jwtPubKey, err := os.Open(jwt_key_file + ".pub"); err == nil {
		defer jwtPubKey.Close()
		if data, err := ioutil.ReadAll(jwtPubKey); err == nil {
			if rsaJWTPub, err = jwt.ParseRSAPublicKeyFromPEM(data); err != nil {
				log.Println(err)
				panic("AD auth enabled but can't read JWT Public key!")
			}
		} else {
			log.Println(err)
			panic("AD auth enabled but can't read JWT Public key!")
		}
	} else {
		log.Println(err)
		panic("AD auth enabled but can't read JWT Public key!")
	}
}

func generateJWT(principal string) string {
	t := jwt.New(jwtSigningMethod)
	t.Claims = &jwt.StandardClaims{
		ExpiresAt: time.Now().Add(time.Minute * 1).Unix(),
		Subject: principal,
		Issuer: "GoTTY",
		Audience: "gotty-users",
	}
	if jwtString, err := t.SignedString(rsaJWTPriv); err == nil {
		return jwtString
	} else {
		log.Printf("Can't generate JWT because: %v, authentication will fail!", err)
		return "garbage"
	}
}

func validJWT(jwtToken string) bool {
	if token, err := jwt.ParseWithClaims(jwtToken, &jwt.StandardClaims{}, func(token *jwt.Token) (interface{}, error) {
		if token.Method != jwtSigningMethod {
			return nil, errors.New("Invalid JWT signing method")
		} else if token.Claims.(*jwt.StandardClaims).Audience != "gotty-users" {
			return nil, errors.New("Invalid JWT audience")
		} else {
			return rsaJWTPub, nil
		}
	}); err != nil {
		log.Println(err)
		return false
	} else {
		log.Printf("Subject Authenticated! Connection given to: %s", token.Claims.(*jwt.StandardClaims).Subject)
		return token.Valid
	}
}
