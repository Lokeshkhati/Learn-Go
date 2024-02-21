// user.go
package main

import (
	"context"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"

	sibApiV3Sdk "github.com/getbrevo/brevo-go/lib"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var JWTSecretKey = []byte("your_secret_key")

type User struct {
	ID          primitive.ObjectID `bson:"_id,omitempty"`
	Name        string             `bson:"name" binding:"required"`
	Email       string             `bson:"email" binding:"required,email"`
	Password    string             `bson:"password" binding:"required"`
	Token       string             `bson:"token,omitempty"`
	TokenExpiry time.Time          `bson:"tokenExpiry,omitempty"`
}

// signup handles user registration
func signup(c *gin.Context, collection *mongo.Collection) {
	var newUser User
	if err := c.ShouldBindJSON(&newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Check if the email is unique
	existingUser, _ := FindUserByEmail(collection, newUser.Email)
	if existingUser.ID != primitive.NilObjectID {
		c.JSON(http.StatusConflict, gin.H{"error": "Email already exists"})
		return
	}

	// Hash the password using bcrypt
	hashedPassword, err := hashPassword(newUser.Password)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	newUser.Password = hashedPassword

	// Insert the user into the database
	_, err = collection.InsertOne(context.TODO(), newUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User registered successfully"})
}

// signin handles user login
func signin(c *gin.Context, collection *mongo.Collection) {
	var loginUser struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&loginUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Find the user by email
	existingUser, err := FindUserByEmail(collection, loginUser.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	// Verify the password using bcrypt
	if !verifyPassword(existingUser.Password, loginUser.Password) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid password"})
		return
	}

	// Generate JWT token
	token, err := generateJWT(existingUser.ID.Hex())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate JWT"})
		return
	}

	// Provide the JWT token in the response
	c.JSON(http.StatusOK, gin.H{"token": token, "user": existingUser, "message": "Login successful"})
}

// FindUserByEmail finds a user by email
func FindUserByEmail(collection *mongo.Collection, email string) (User, error) {
	var user User
	err := collection.FindOne(context.Background(), bson.M{"email": email}).Decode(&user)
	return user, err
}

// hashPassword hashes the user password using bcrypt
func hashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// verifyPassword verifies the user password using bcrypt
func verifyPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}

// generateJWT generates a JWT token for the given user ID
func generateJWT(userID string) (string, error) {
	claims := jwt.MapClaims{
		"user_id": userID,
		"exp":     time.Now().Add(time.Hour * 24).Unix(), // Token expires in 24 hours
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString(JWTSecretKey)
	if err != nil {
		return "", err
	}

	return signedToken, nil
}

// InsertUser inserts a new user into the database
func InsertUser(user User) (*mongo.InsertOneResult, error) {
	result, err := collection.InsertOne(context.TODO(), user)
	return result, err
}

// GetAllUsers retrieves all users from the database
func GetAllUsers() ([]User, error) {
	cursor, err := collection.Find(context.TODO(), bson.D{})
	if err != nil {
		return nil, err
	}
	defer cursor.Close(context.TODO())

	var users []User
	err = cursor.All(context.TODO(), &users)
	if err != nil {
		return nil, err
	}

	return users, nil
}

// FindUserByID finds a user by ID
func FindUserByID(id primitive.ObjectID) (User, error) {
	var user User
	filter := bson.M{"_id": id}

	err := collection.FindOne(context.TODO(), filter).Decode(&user)
	return user, err
}

func UpdateUser(id primitive.ObjectID, updatedUser User) (*mongo.UpdateResult, error) {
	filter := bson.M{"_id": id}
	update := bson.M{"$set": updatedUser}

	result, err := collection.UpdateOne(context.TODO(), filter, update)
	return result, err
}

// DeleteUser deletes a user from the database
func DeleteUser(id primitive.ObjectID) (*mongo.DeleteResult, error) {
	filter := bson.M{"_id": id}

	result, err := collection.DeleteOne(context.TODO(), filter)
	return result, err
}

// createUser handles the creation of a new user
func createUser(c *gin.Context) {
	var newUser User
	if err := c.ShouldBindJSON(&newUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	result, err := InsertUser(newUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": result.InsertedID})
}

// getUsers retrieves all users
func getUsers(c *gin.Context) {
	users, err := GetAllUsers()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, users)
}

// getUserByID retrieves a user by ID
func getUserByID(c *gin.Context) {
	userID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	user, err := FindUserByID(userID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, user)
}

// updateUser updates a user by ID
func updateUser(c *gin.Context) {
	userID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	var updatedUser User
	if err := c.ShouldBindJSON(&updatedUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	updateResult, err := UpdateUser(userID, updatedUser)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if updateResult.ModifiedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User updated successfully"})
}

type (
	ParamsInterface interface {
		ParamsInterfaceMethod() string
	}

	ParamsType struct {
		resetLink string
	}
)

func (m ParamsType) ParamsInterfaceMethod() string {
	return m.resetLink
}

// deleteUser deletes a user by ID
func deleteUser(c *gin.Context) {
	userID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid ID"})
		return
	}

	deleteResult, err := DeleteUser(userID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	if deleteResult.DeletedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User deleted successfully"})
}

func forgotPassword(c *gin.Context, collection *mongo.Collection) {
	var emailData struct {
		Email string `json:"email" binding:"required,email"`
	}

	if err := c.ShouldBindJSON(&emailData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := FindUserByEmail(collection, emailData.Email)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	resetToken := generateResetToken()

	// Update user object with new token and token expiry
	user.Token = resetToken
	user.TokenExpiry = time.Now().Add(time.Hour * 1)

	// Update the user in the database with the new token and token expiry
	userId, err := primitive.ObjectIDFromHex("65d4a6b609a1945b201d946b")
	if err != nil {
		return
	}
	filter := bson.M{"_id": userId}
	update := bson.M{
		"$set": bson.M{
			"token":       user.Token,
			"tokenExpiry": user.TokenExpiry,
		},
	}

	result, err := collection.UpdateOne(context.TODO(), filter, update)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	// Check if any documents were modified
	if result.ModifiedCount == 0 {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "User update failed: no documents modified"})
		return
	}

	resetUrl := "http://localhost:3000/reset-password/" + resetToken

	SendResetPasswordEmail(c, user.Email, resetUrl)

	c.JSON(http.StatusOK, gin.H{"message": "Password reset email sent"})
}

func resetPassword(c *gin.Context, collection *mongo.Collection) {
	var resetData struct {
		ResetToken      string `json:"reset_token" binding:"required"`
		NewPassword     string `json:"new_password" binding:"required"`
		ConfirmPassword string `json:"confirm_password" binding:"required"`
	}
	if err := c.ShouldBindJSON(&resetData); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	user, err := FindUserByToken(collection, resetData.ResetToken)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
		return
	}

	// Check if the reset token is valid and not expired
	if user.Token != resetData.ResetToken || time.Now().After(user.TokenExpiry) {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired reset token"})
		return
	}

	// Update the password
	hashedPassword, err := hashPassword(resetData.NewPassword)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to hash password"})
		return
	}

	user.Password = hashedPassword
	user.Token = ""
	user.TokenExpiry = time.Time{}

	// Update the user with the new password and clear the reset token
	_, err = UpdateUser(user.ID, user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Password reset successful"})
}

func generateResetToken() string {
	token := uuid.New().String()
	return token
}

func SendResetPasswordEmail(ctx context.Context, to string, resetLink string) error {

	brevoKey := "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"

	params := make(map[string]interface{})
	params["resetLink"] = resetLink
	paramsInterface := interface{}(params)

	// Configure Brevo API client
	cfg := sibApiV3Sdk.NewConfiguration()
	cfg.AddDefaultHeader("api-key", brevoKey)
	cfg.AddDefaultHeader("partner-key", brevoKey)
	sib := sibApiV3Sdk.NewAPIClient(cfg)

	payload := sibApiV3Sdk.SendSmtpEmail{
		To: []sibApiV3Sdk.SendSmtpEmailTo{
			{
				Email: to,
			},
		},
		TemplateId: 5,
		Params:     &paramsInterface,
	}

	// Send the email using Brevo API
	_, _, err := sib.TransactionalEmailsApi.SendTransacEmail(ctx, payload)

	if err != nil {
		return err
	}
	return nil
}

func FindUserByToken(collection *mongo.Collection, token string) (User, error) {

	var user User
	err := collection.FindOne(context.Background(), bson.M{"token": token}).Decode(&user)
	return user, err
}
