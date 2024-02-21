package main

import (
	"fmt"
	"log"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
)

var router *gin.Engine

func init() {

	router = gin.Default()
	router.Use(cors.New(cors.Config{
		AllowOrigins: []string{"http://localhost:3000"},
		AllowMethods: []string{"POST", "GET", "PUT", "PATCH", "OPTIONS", "DELETE"},
		AllowHeaders: []string{"*"},
	}))

	// Define API routes
	setupRoutes()
}

func setupRoutes() {

	// Signup
	router.POST("/signup", func(c *gin.Context) {
		signup(c, collection)
	})

	// Signin
	router.POST("/signin", func(c *gin.Context) {
		signin(c, collection)
	})
	// Create a new user
	router.POST("/users", createUser)

	// Get all users
	router.GET("/users", getUsers)

	// Get a user by ID
	router.GET("/users/:id", getUserByID)

	// Update a user by ID
	router.PUT("/users/:id", updateUser)

	// Delete a user by ID
	router.DELETE("/users/:id", deleteUser)
	router.POST("/forgot-password", func(c *gin.Context) {
		forgotPassword(c, collection)
	})
	router.POST("/reset-password", func(c *gin.Context) {
		resetPassword(c, collection)
	})
}

func main() {
	// Run the Gin server
	serverPort := ":8080"
	fmt.Printf("Server is running on http://localhost%s\n", serverPort)
	log.Fatal(router.Run(serverPort))
}
