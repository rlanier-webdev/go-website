package main

import (
	"database/sql"
	"net/http"
	"strings"
	"text/template"

	"github.com/gorilla/sessions"
	"golang.org/x/crypto/bcrypt"
)

var store = sessions.NewCookieStore([]byte("your-secret-key"))

type GreetingData struct {
	Name string
}

type LoginData struct {
	Message string
}

// Handler for the home page
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	// Retrieve the session
	session, _ := store.Get(r, "session-name")

	// Get the username from the session
	username, ok := session.Values["username"].(string)
	if !ok {
		http.Redirect(w, r, "/login", http.StatusFound) // Redirect to login if not authenticated
		return
	}

	// Parse the index.html template
	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	// Execute the template, passing in the username
	tmpl.Execute(w, map[string]string{"Username": username})
}

// Handler for the registration page
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/register.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		username := strings.TrimSpace(r.Form.Get("username"))
		password := r.Form.Get("password")

		if username == "" || password == "" {
			tmpl.Execute(w, map[string]string{"Message": "Username and password cannot be empty"})
			return
		}

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		_, err = DB.Exec("INSERT INTO users (username, password) VALUES (?, ?)", username, string(hashedPassword))
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE constraint failed") {
				tmpl.Execute(w, map[string]string{"Message": "Username already exists"})
			} else {
				tmpl.Execute(w, map[string]string{"Message": "Error registering user"})
			}
			return
		}

		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}

	tmpl.Execute(w, nil)
}

// Handler for the login page
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("templates/login.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		username := strings.TrimSpace(r.Form.Get("username"))
		password := r.Form.Get("password")

		if verifyLogin(DB, username, password) {
			// Create a session and set the username
			session, _ := store.Get(r, "session-name")
			session.Values["username"] = username
			session.Save(r, w)

			http.Redirect(w, r, "/", http.StatusFound)
			return
		}

		err = tmpl.Execute(w, LoginData{Message: "Invalid username or password"})
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		return
	}

	tmpl.Execute(w, nil)
}

func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	// Get the session
	session, _ := store.Get(r, "session-name")

	// Clear the session data
	session.Values["username"] = ""
	session.Options.MaxAge = -1 // This expires the session

	// Save the session changes
	session.Save(r, w)

	// Redirect to the login page
	http.Redirect(w, r, "/", http.StatusFound)
}

// Function to verify login credentials
func verifyLogin(db *sql.DB, username, password string) bool {
	var hashedPassword string
	err := db.QueryRow("SELECT password FROM users WHERE username = ?", username).Scan(&hashedPassword)
	if err != nil {
		if err == sql.ErrNoRows {
			return false // User not found
		}
		return false
	}

	err = bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}
