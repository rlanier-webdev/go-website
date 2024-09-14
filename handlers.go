package main

import (
	"database/sql"
	"net/http"
	"strings"
	"text/template"

	"golang.org/x/crypto/bcrypt"
)

type GreetingData struct {
	Name string
}

type LoginData struct {
	Message string
}

// Handler for the home page
func HomeHandler(w http.ResponseWriter, r *http.Request) {
	username := r.URL.Query().Get("username")

	data := map[string]string{
		"Username": username,
	}

	tmpl, err := template.ParseFiles("templates/index.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

// Handler for the registration page
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		username := strings.TrimSpace(r.Form.Get("username"))
		password := r.Form.Get("password")

		if username == "" || password == "" {
			tmpl, _ := template.ParseFiles("templates/register.html")
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
			tmpl, _ := template.ParseFiles("templates/register.html")
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

	tmpl, err := template.ParseFiles("templates/register.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	tmpl.Execute(w, nil)
}

// Handler for the login page
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		err := r.ParseForm()
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		username := strings.TrimSpace(r.Form.Get("username"))
		password := r.Form.Get("password")

		if verifyLogin(DB, username, password) {
			http.Redirect(w, r, "/?username="+username, http.StatusFound)
			return
		}

		tmpl, err := template.ParseFiles("templates/login.html")
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		err = tmpl.Execute(w, LoginData{Message: "Invalid username or password"})
		if err != nil {
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		return
	}

	tmpl, err := template.ParseFiles("templates/login.html")
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}

	err = tmpl.Execute(w, nil)
	if err != nil {
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
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
