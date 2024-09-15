package main

import (
	"database/sql"
	"fmt"
	"net/http"

	_ "github.com/glebarez/sqlite"
	"github.com/gorilla/mux"
)

// Global variable for the database
var DB *sql.DB

func main() {
	var err error
	DB, err = initDB()
	if err != nil {
		fmt.Println("Error initializing database:", err)
		return
	}
	defer DB.Close()

	router := mux.NewRouter()

	// Register the handlers from handlers.go
	router.HandleFunc("/", HomeHandler).Methods(http.MethodGet)
	router.HandleFunc("/login", LoginHandler).Methods(http.MethodGet, http.MethodPost)
	router.HandleFunc("/register", RegisterHandler).Methods(http.MethodGet, http.MethodPost)
	router.HandleFunc("/logout", LogoutHandler).Methods(http.MethodGet, http.MethodPost)


	// Serve static files from the "static" directory
	router.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))

	fmt.Println("Server is listening on :8080...")
	err = http.ListenAndServe(":8080", router)
	if err != nil {
		fmt.Println("Error starting server:", err)
	}
}

// Database initialization function
func initDB() (*sql.DB, error) {
	db, err := sql.Open("sqlite", "./app.db")
	if err != nil {
		return nil, err
	}

	_, err = db.Exec(`
	CREATE TABLE IF NOT EXISTS users (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		username TEXT NOT NULL UNIQUE,
		password TEXT NOT NULL
	)
	`)
	if err != nil {
		return nil, err
	}

	return db, nil
}
