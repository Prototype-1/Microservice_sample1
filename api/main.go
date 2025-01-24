package main

import (
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/dgrijalva/jwt-go"
)

var MySigninKey = []byte(os.Getenv("SECRET_KEY"))

func homePage(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintf(w, "Fine its working now!!!")
}

func isAuthorized(endpoint func(http.ResponseWriter, *http.Request)) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" {
			fmt.Fprintf(w, "No authorization token provided")
			return
		}
		tokenString := ""
		_, err := fmt.Sscanf(authHeader, "Bearer %s", &tokenString)
		if err != nil {
			fmt.Fprintf(w, "Invalid token format")
			return
		}

		// Parse token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("Invalid signing method")
			}

			aud := "billing.jwtgo.io"
			checkAudience := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
			if !checkAudience {
				return nil, fmt.Errorf("Invalid audience")
			}

			iss := "jwtgo.io"
			checkIssuer := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
			if !checkIssuer {
				return nil, fmt.Errorf("Invalid issuer")
			}

			return MySigninKey, nil
		})

		if err != nil {
			fmt.Fprintf(w, err.Error())
			return
		}

		if token.Valid {
			endpoint(w, r)
		} else {
			fmt.Fprintf(w, "Invalid token")
		}
	})
}

func handleRequests() {
	http.Handle("/", isAuthorized(homePage))
	log.Fatal(http.ListenAndServe(":9090", nil))
}

func main() {
	fmt.Printf("Server running, you are good to go...")
	handleRequests()
}
