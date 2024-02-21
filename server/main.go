package main

import (
	"context"
	"log"
	"net/http"
	"time"

	"github.com/gin-contrib/sessions"
	"github.com/gin-contrib/sessions/cookie"
	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Name     string `json:"name"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

var collection *mongo.Collection

func main() {

	uri := "mongodb+srv://finsig:finsig404@cluster0.k8say3c.mongodb.net/"
	clientOptions := options.Client().ApplyURI(uri)
	r := gin.Default()

	// Create a new client
	client, err := mongo.Connect(context.TODO(), clientOptions)
	if err != nil {
		panic(err)
	}
	defer client.Disconnect(context.TODO())

	// Ping the server to check the connection
	err = client.Ping(context.TODO(), nil)
	if err != nil {
		panic(err)
	}
	println("Connected to MongoDB!")

	store := cookie.NewStore([]byte("secret"))
	store.Options(sessions.Options{
		MaxAge: int((time.Minute * 2).Seconds()), // 2 minutes
		Path:   "/",
	})
	// Set up the Gin engine:

	// Use the session middleware:
	r.Use(sessions.Sessions("mysession", store))

	collection = client.Database("test").Collection("users")

	indexModel := mongo.IndexModel{
		Keys: bson.M{
			"email": 1,
		},
		Options: options.Index().SetUnique(true),
	}
	_, err = collection.Indexes().CreateOne(context.TODO(), indexModel)
	if err != nil {
		log.Fatal(err)
	}
	r.GET("/ping", hello)
	r.GET("/private", AuthRequired(), hello)
	r.POST("/signup", adduser)
	r.POST("/login", login)
	err = r.Run("localhost:8080")
	if err != nil {
		log.Fatalf("impossible to start server: %s", err)
	}

}

func hello(c *gin.Context) {
	c.IndentedJSON(http.StatusOK, "pong")
}

func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		session := sessions.Default(c)
		user := session.Get("user")
		if user == nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
			c.Abort()
			return
		}
		// Continue down the chain to handle the request
		c.Next()
	}
}

func adduser(c *gin.Context) {
	var user User

	if err := c.BindJSON(&user); err != nil {
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Error hashing password"})
		return
	}
	user.Password = string(hashedPassword)

	_, err = collection.InsertOne(context.Background(), user)
	if mongo.IsDuplicateKeyError(err) {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Email already exists"})
		return
	} else if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Internal Server Error"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"message": "User added successfully"})
}

func login(c *gin.Context) {
	var user User
	var foundUser User

	if err := c.BindJSON(&user); err != nil {
		return
	}

	err := collection.FindOne(context.TODO(), bson.M{"email": user.Email}).Decode(&foundUser)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "Email not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"message": "Internal Server Error"})
		}
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(foundUser.Password), []byte(user.Password))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Incorrect password"})
		return
	}

	session := sessions.Default(c)
	session.Set("user", user.Email)
	err = session.Save()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to save session"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Logged in successfully"})
}
