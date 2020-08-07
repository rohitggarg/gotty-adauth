package server

import (
	"encoding/base64"
	"log"
	"net/http"
	"strings"
	auth "github.com/korylprince/go-ad-auth"
)

func (server *Server) wrapLogger(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rw := &logResponseWriter{w, 200}
		handler.ServeHTTP(rw, r)
		log.Printf("%s %d %s %s", r.RemoteAddr, rw.status, r.Method, r.URL.Path)
	})
}

func (server *Server) wrapHeaders(handler http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// todo add version
		w.Header().Set("Server", "GoTTY")
		handler.ServeHTTP(w, r)
	})
}

func (server *Server) wrapAdAuth(handler http.Handler, ad_server_addr string, ad_group string) http.Handler {
	
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "auth_token.js") {
			handler.ServeHTTP(w, r)
			return
		}
		token := strings.SplitN(r.Header.Get("Authorization"), " ", 2)

		if len(token) != 2 || strings.ToLower(token[0]) != "basic" {
			w.Header().Set("WWW-Authenticate", `Basic realm="GoTTY"`)
			http.Error(w, "Bad Request", http.StatusUnauthorized)
			return
		}

		payload, err := base64.StdEncoding.DecodeString(token[1])
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		if !server.validADCredential(ad_server_addr, ad_group, string(payload)) {
			w.Header().Set("WWW-Authenticate", `Basic realm="GoTTY"`)
			http.Error(w, "authorization failed", http.StatusUnauthorized)
			return
		}

		log.Printf("Basic Authentication Succeeded: %s", r.RemoteAddr)
		handler.ServeHTTP(w, r)
	})
}

func (server *Server) validADCredential(ad_server_addr string, ad_group string, payload string) bool {
	config := &auth.Config{
    Server:   ad_server_addr,
    Port:     389,
    BaseDN:   server.options.ADServerBaseDN,
	}
	credential := strings.SplitN(payload, ":", 2)

	status, entry, _, err := auth.AuthenticateExtended(config, credential[0], credential[1], []string{"memberOf"}, []string{})

	if err != nil {
		log.Printf("Failed to authenticate principal %s, err: %v", credential[0], err)
		return false
	}

	if !status {
		log.Printf("Re check password for principal %s", credential[0])
		return false
	}

	foundGroup := false
	for _, attr := range entry.Attributes {
		if attr.Name == "memberOf" {
			for _, val := range attr.Values {
				if strings.HasPrefix(val, "CN=" + ad_group) {
					log.Printf("Part of - %s", val)
					foundGroup = true
					break;
				}
			}
		}
	}

	return foundGroup
}
