package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

const db = "forlogin"
const col = "details"

var jwtKey = []byte("secret")

var cookie http.Cookie
var client *mongo.Client

type StandardClaims struct {
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	Id        string `json:"jti,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`
	Issuer    string `json:"iss,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	Subject   string `json:"sub,omitempty"`
}

type Credentials struct {
	ID       primitive.ObjectID `json:"_id"`
	Username string             `json:"username"`
	Password string             `json:"password"`
	//FirstName string `json:"firstname" bson:"firstname"`
	//LastName  string `json:"lastname" bson:"lastname"`
	Email string `json:"email" `
	//Password  string `json:"password" bson:"password"`
}

type Claims struct {
	Username string `json:"username"`

	Email string `json:"email"`

	jwt.StandardClaims
}

func getHash(pwd []byte) string {
	hash, err := bcrypt.GenerateFromPassword(pwd, bcrypt.MinCost)
	if err != nil {
		log.Println(err)
	}
	return string(hash)
}

func AuthRequired(handler http.HandlerFunc) http.HandlerFunc {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		//var  *jwt.Claims

		tokenString := r.Header.Get("Authorization")
		// t := token[6:]

		key := strings.Replace(tokenString, "Bearer ", "", -1)
		fmt.Println(key)

		cookie, _ := r.Cookie("token")
		tokenStr := cookie.Value
		fmt.Println(tokenStr)

		if key == tokenStr {
			token, err := jwt.Parse(key, func(token *jwt.Token) (interface{}, error) {
				if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
					return nil, fmt.Errorf("there was an error in parsing")
				}
				return jwtKey, nil
			})
			if err != nil {
				fmt.Println(err)
			}
			if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
				fmt.Println(claims)
			}

			handler.ServeHTTP(w, r)
		}
	})
}

func Type(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-ID", "1234")
		log.Println(r.RequestURI)

		next.ServeHTTP(w, r)
	})
}

func userSignup(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	var user Credentials
	json.NewDecoder(request.Body).Decode(&user)
	user.Password = getHash([]byte(user.Password))
	collection := client.Database(db).Collection(col)
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	result, _ := collection.InsertOne(ctx, user)
	json.NewEncoder(response).Encode(result)

}

func Login(w http.ResponseWriter, r *http.Request) {
	var credentials Credentials
	var dbcredentials Credentials
	err := json.NewDecoder(r.Body).Decode(&credentials)
	collection := client.Database(db).Collection(col)
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)
	err = collection.FindOne(ctx, bson.M{"email": credentials.Email}).Decode(&dbcredentials)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	userPass := []byte(credentials.Password)
	dbPass := []byte(dbcredentials.Password)

	passErr := bcrypt.CompareHashAndPassword(dbPass, userPass)

	if passErr != nil {
		log.Println(passErr)
		w.Write([]byte(`{"response":"Wrong Password!"}`))
		return
	}
	expirationTime := time.Now().Add(time.Minute * 5)
	claims := &Claims{
		Username: credentials.Username,
		Email:    credentials.Email,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	http.SetCookie(w,
		&http.Cookie{
			Name:    "token",
			Value:   tokenString,
			Expires: expirationTime,
		})

}
func logout(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w,
		&http.Cookie{
			Name:    "token",
			Value:   "",
			Expires: time.Now().Add(-time.Minute),
		})
	w.Write([]byte(fmt.Sprintf("Successfully Logged out")))
}

func ChangePassword(response http.ResponseWriter, request *http.Request) {
	c := make(map[string]interface{})
	json.NewEncoder(response).Encode(c)
	var credentials Credentials

	_ = json.NewDecoder(request.Body).Decode(&credentials)
	credentials.Password = getHash([]byte(credentials.Password))
	filter := bson.M{"email": credentials.Email}
	update := bson.M{
		"$set": credentials,
	}

	collection := client.Database(db).Collection(col)
	ctx, _ := context.WithTimeout(context.Background(), 5*time.Second)
	getresult, err := collection.UpdateOne(ctx, filter, update)
	if err != nil {
		fmt.Println(err)
		c["error"] = "an error encountered"
		json.NewEncoder(response).Encode(c)
		return
	}
	json.NewEncoder(response).Encode(getresult)

}

func Home(w http.ResponseWriter, r *http.Request) {

	cookie, err := r.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			fmt.Println("err1")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	tokenStr := cookie.Value

	claims := &Claims{}

	tkn, err := jwt.ParseWithClaims(tokenStr, claims,
		func(t *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

	if err != nil {
		if err == jwt.ErrSignatureInvalid {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if !tkn.Valid {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.Write([]byte(fmt.Sprintf("userdetails :\n  Email of user : %s\n  Username of user :     \n", claims.Email, claims.Username)))

}

func main() {
	fmt.Println("Starting the application")

	r := mux.NewRouter()
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second)

	client, _ = mongo.Connect(ctx, options.Client().ApplyURI("mongodb://localhost:27017"))
	r.Use(Type)
	r.HandleFunc("/signin", userSignup).Methods("POST")
	r.HandleFunc("/login", Login)
	r.HandleFunc("/home", Home)
	r.HandleFunc("/login/changepwd", AuthRequired(ChangePassword)).Methods("PATCH")
	r.HandleFunc("/logout", logout)
	methods := handlers.AllowedMethods([]string{"GET", "POST", "PUT", "PATCH"})
	origins := handlers.AllowedMethods([]string{"*"})
	log.Fatal(http.ListenAndServe(":8080", handlers.CORS(methods, origins)(r)))
}
