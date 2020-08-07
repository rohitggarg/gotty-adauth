package server

import (
	"crypto/rsa"
	"os"
	"io/ioutil"
	jwt "github.com/dgrijalva/jwt-go"
)

var rsaJWTPriv *rsa.PrivateKey
var rsaJWTPub *rsa.PublicKey

func openAndParseKey(jwt_key_file string) {
	if jwtPrivKey, err := os.Open(jwt_key_file); err == nil {
		defer jwtPrivKey.Close()
		if data, err := ioutil.ReadAll(jwtPrivKey); err == nil {
			if rsaJWTPriv, err = jwt.ParseRSAPrivateKeyFromPEM(data); err != nil {
				panic("AD auth enabled but can't read JWT Private key!", err)
			}
		} else {
			panic("AD auth enabled but can't read JWT Private key!", err)
		}
	} else {
		panic("AD auth enabled but can't read JWT Private key!", err)
	}

	if jwtPubKey, err := os.Open(jwt_key_file + ".pub"); err == nil {
		defer jwtPubKey.Close()
		if data, err = ioutil.ReadAll(jwtPubKey); err == nil {
			if rsaJWTPub, err = jwt.ParseRSAPublicKeyFromPEM(data); err != nil {
				panic("AD auth enabled but can't read JWT Public key!", err)
			}
		} else {
			panic("AD auth enabled but can't read JWT Public key!", err)
		}
	} else {
		panic("AD auth enabled but can't read JWT Public key!", err)
	}
}

func generateJWT(principal string) string {
	return "test"
}

func validJWT(jwt string) bool {
	return true
}
