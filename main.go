package main

import (
	"bytes"
	"fmt"
	"image/png"
	"log"
	"math/rand"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

var mu sync.Mutex
var accounts = make(map[string]*otp.Key)
var letterRunes = []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ")

const issuer = "totp-issuer@example.com"

func init() {
	rand.Seed(time.Now().UnixNano())
}

func main() {
	m := mux.NewRouter()

	m.HandleFunc("/", mainHandler).Methods("GET")
	m.HandleFunc("/login/{username}", loginHandler).Methods("GET")
	m.HandleFunc("/new", generateNewHandler).Methods("GET")
	m.HandleFunc("/generate", generateHandler).Methods("GET")
	m.HandleFunc("/verify", verifyHandler).Methods("POST")
	m.HandleFunc("/success", successHandler).Methods("GET")

	server := &http.Server{
		Handler:      m,
		Addr:         ":8899",
		WriteTimeout: 15 * time.Second,
		ReadTimeout:  15 * time.Second,
	}

	log.Printf("Server exit: %v", server.ListenAndServe())
}

func mainHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "<a href=\"/new\">Generate new account</a> or log into existing:<p>")
	for accountName, _ := range accounts {
		fmt.Fprintf(w, "<li><a href=\"/login/%s\">%s</a>", accountName, accountName)
	}
}

func successHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	fmt.Fprint(w, "Success, go back to <a href=\"/\">main page</a>")
}

func generateNewHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprint(w, `
<html>
    <head>
    <title></title>
    </head>
    <body>
      <img src="/generate">
      <p>
      <a href="/">Return to main page</a>
    </body>
</html>
`)
}

func generateHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	defer mu.Unlock()

	// Ensure we produce an account that is new
	var account string
	for {
		account = generateAccountName(10)
		if _, ok := accounts[account]; !ok {
			break
		}
	}

	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      issuer,
		AccountName: account,
	})
	if err != nil {
		http.Error(w, fmt.Sprintf("Error generating key: %v", err), http.StatusInternalServerError)
		return
	}

	// Update the map of accounts
	accounts[account] = key

	// Generate QR code
	img, err := key.Image(256, 256)
	if err != nil {
		http.Error(w, fmt.Sprintf("Error generating image: %v", err), http.StatusInternalServerError)
		return
	}

	var buf bytes.Buffer
	png.Encode(&buf, img)

	w.Header().Set("Content-Type", "image/png")
	_, err = w.Write(buf.Bytes())
	if err != nil {
		log.Printf("Error writing image to http client: %v", err)
		return
	}
}

func verifyHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	username := r.Form["username"][0]
	if username == "" {
		http.Error(w, "username not given", http.StatusBadRequest)
		return
	}

	key := r.Form["key"][0]
	if key == "" {
		http.Error(w, "key not given", http.StatusBadRequest)
		return
	}

	mu.Lock()
	defer mu.Unlock()
	userKey, ok := accounts[username]
	if !ok {
		http.Error(w, "account not found", http.StatusUnauthorized)
		return
	}

	log.Printf("username = '%s', key = '%s', userKey = '%s'", username, key, userKey)

	result := totp.Validate(key, userKey.Secret())
	if result {
		http.Error(w, "invalid key", http.StatusUnauthorized)
		return
	}

	http.Redirect(w, r, "/success", 301)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	params := mux.Vars(r)
	username := params["username"]

	doc := fmt.Sprintf(`
<html>
    <head>
    <title></title>
    </head>
    <body>
        Remember to include space!
        <form action="/verify" method="post">
            Username:<input type="text" name="username" value="%s"><br>
            Password:<input type="text" name="key"><br>
            <input type="submit" value="Login"><br>
        </form>
    </body>
</html>
`, username)

	w.Write([]byte(doc))
}

func generateAccountName(n int) string {
	b := make([]rune, n)
	for i := range b {
		b[i] = letterRunes[rand.Intn(len(letterRunes))]
	}
	return "account-" + string(b)
}
