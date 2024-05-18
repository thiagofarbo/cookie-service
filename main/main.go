package main

import (
	"bytes"
	"cookie.com/cookie-example/main/internal/cookies"
	"cookie.com/cookie-example/main/internal/domain"
	gob "encoding/gob"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
)

var secretKey []byte

func main() {

	gob.Register(&domain.User{})

	var err error

	secretKey, err = hex.DecodeString("13d6b4dff8f84a10851021ec8608f814570d562c92fe6b5ec4c9f595bcb3234b")
	if err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/set", setCookieHandler)
	mux.HandleFunc("/get", getCookieHandler)

	log.Print("Listening...")
	err = http.ListenAndServe(":4000", mux)

	if err != nil {
		log.Fatal(err)
	}
}

func setCookieHandler(w http.ResponseWriter, r *http.Request) {

	user := domain.User{Name: "Thiago", Age: 36}

	// Initialize a buffer to hold the gob-encoded data.
	var buf bytes.Buffer

	// Gob-encode the user data, storing the encoded output in the buffer.
	err := gob.NewEncoder(&buf).Encode(user)
	if err != nil {
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
	}

	cookie := http.Cookie{
		Name:     "cookie",
		Value:    buf.String(),
		Path:     "/",
		MaxAge:   3600,
		HttpOnly: true,
		Secure:   true,
		SameSite: http.SameSiteLaxMode,
	}

	// Write an encrypted cookie containing the gob-encoded data as normal.
	err = cookies.WriteEncrypted(w, cookie, secretKey)
	if err != nil {
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	w.Write([]byte("cookie set!"))
}

func getCookieHandler(w http.ResponseWriter, r *http.Request) {

	gobEncodedValue, err := cookies.ReadEncrypted(r, "cookie", secretKey)

	if err != nil {
		switch {
		case errors.Is(err, http.ErrNoCookie):
			http.Error(w, "No cookie found", http.StatusBadRequest)

		case errors.Is(err, cookies.ErrInvalidValue):
			http.Error(w, "Invalid cookie", http.StatusBadRequest)
		default:
			log.Println(err)
			http.Error(w, "server error", http.StatusInternalServerError)
		}
		return
	}

	var user domain.User

	reader := strings.NewReader(gobEncodedValue)

	// Decode it into the User type. Notice that we need to pass a *pointer* of the User
	err = gob.NewDecoder(reader).Decode(&user)

	if err != nil {
		log.Println(err)
		http.Error(w, "server error", http.StatusInternalServerError)
		return
	}
	fmt.Fprintf(w, "Name: %q\n", user.Name)
	fmt.Fprintf(w, "Age: %d\n", user.Age)

	//w.Write([]byte(value))
}
