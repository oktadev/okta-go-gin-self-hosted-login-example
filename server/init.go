package server

import (
	"log"
	"os"
	"time"

	"github.com/gin-gonic/contrib/static"
	"github.com/gin-gonic/gin"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	idx "github.com/okta/okta-idx-golang"
	"github.com/patrickmn/go-cache"
)

const (
	SESSION_STORE_NAME = "okta-self-hosted-session-store"
)

// Utilized to store meta data that is also used to drive the app UX templates
type LoginData struct {
	IsAuthenticated     bool
	BaseUrl             string
	ClientId            string
	RedirectURI         string
	Issuer              string
	State               string
	InteractionHandle   string
	CodeChallenge       string
	CodeChallengeMethod string
	OTP                 string
	Lang                string
}

// Internal Struct around the Server to use with the sample app.
type Server struct {
	port         string
	idxClient    *idx.Client
	sessionStore *sessions.CookieStore
	cache        *cache.Cache
	LoginData    LoginData
	router       *gin.Engine
}

func NewServer() *Server {
	godotenv.Load("./.okta.env")

	port := os.Getenv("PORT")

	if port == "" {
		port = "8080" // default when missing
	}

	idxClient, err := idx.NewClientWithSettings(
		idx.WithClientID(os.Getenv("OKTA_OAUTH2_CLIENT_ID")),
		idx.WithClientSecret(os.Getenv("OKTA_OAUTH2_CLIENT_SECRET")),
		idx.WithIssuer(os.Getenv("OKTA_OAUTH2_ISSUER")),
		idx.WithScopes([]string{"openid", "profile", "email", "offline_access"}),
		idx.WithRedirectURI("http://localhost:"+port+"/callback"),
	)
	if err != nil {
		log.Fatalf("new client error: %+v", err)
	}

	return &Server{
		port:         port,
		idxClient:    idxClient,
		sessionStore: sessions.NewCookieStore([]byte(SESSION_STORE_NAME)),
		cache:        cache.New(5*time.Minute, 10*time.Minute),
		router:       gin.Default(), // Set the router as the default one shipped with Gin
	}
}

func (s *Server) Init() {

	// Serve HTML templates
	s.router.LoadHTMLGlob("./templates/*")
	// Serve frontend static files
	s.router.Use(static.Serve("/static", static.LocalFile("./static", true)))

	// setup public routes
	s.router.GET("/", s.IndexHandler)
	s.router.GET("/login", s.LoginHandler)
	s.router.GET("/callback", s.AuthCodeCallbackHandler)
	s.router.POST("/logout", s.LogoutHandler)
	s.router.GET("/profile", s.ProfileHandler)

	// Start and run the server
	log.Printf("Running on http://localhost:" + s.port)
	s.router.Run(":" + s.port)
}
