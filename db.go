package main

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var collection *mongo.Collection

func init() {
	// Initialize and connect to the database
	client, err := ConnectDB()
	if err != nil {
		panic(err)
	}

	// Set the "users" collection
	collection = client.Database("go-auth").Collection("users")
}

const dbUrl = "url"

// ConnectDB establishes a connection to MongoDB and returns a client
func ConnectDB() (*mongo.Client, error) {
	// Set client options
	clientOptions := options.Client().ApplyURI(dbUrl)
	// Connect to MongoDB
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		return nil, err
	}

	// Check the connection
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		return nil, err
	}

	fmt.Println("Connected to MongoDB!")

	return client, nil
}
