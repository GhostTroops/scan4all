package server

import (
	"fmt"
	"github.com/fatih/color"
	"log"
	"net/http"
	"os"
	"path"
	"time"

	jwt "github.com/appleboy/gin-jwt/v2"
	"github.com/hktalent/jaeles/database"
	"github.com/hktalent/jaeles/libs"
	"github.com/hktalent/jaeles/utils"

	"github.com/gin-contrib/cors"
	"github.com/gin-contrib/static"
	"github.com/gin-gonic/gin"
)

type login struct {
	Username string `form:"username" json:"username" binding:"required"`
	Password string `form:"password" json:"password" binding:"required"`
}

var identityKey = "id"

// User struct
type User struct {
	UserName string
	Role     string
	Email    string
	IsAdmin  bool
}

// InitRouter start point of api server
func InitRouter(options libs.Options, result chan libs.Record) {
	// turn off Gin debug mode
	if !options.Debug {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.New()
	r.Use(gin.Logger())
	r.Use(gin.Recovery())

	if options.Server.NoAuth {
		fmt.Fprintf(os.Stderr, "[Warning] You're running server with %v\n", color.RedString("NO AUTHENTICATION"))
	}

	// default is ~/.jaeles/ui/
	uiPath := path.Join(options.RootFolder, "/plugins/ui")
	r.Use(static.Serve("/", static.LocalFile(uiPath, true)))

	allowOrigin := "*"
	secret := "something you have to change"
	if options.Server.JWTSecret != "" {
		secret = options.Server.JWTSecret
	}
	if options.Server.Cors != "" {
		allowOrigin = options.Server.Cors
	}

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{allowOrigin},
		AllowMethods:     []string{"POST", "GET", "OPTIONS"},
		AllowHeaders:     []string{"Authorization"},
		AllowCredentials: true,
		MaxAge:           24 * time.Hour,
	}))

	// the jwt middleware
	authMiddleware, err := jwt.New(&jwt.GinJWTMiddleware{
		Realm:       "jaeles server",
		Key:         []byte(secret),
		Timeout:     time.Hour * 360,
		MaxRefresh:  time.Hour * 720,
		IdentityKey: identityKey,
		PayloadFunc: func(data interface{}) jwt.MapClaims {
			if v, ok := data.(*User); ok {
				return jwt.MapClaims{
					identityKey: v.Role,
				}
			}
			return jwt.MapClaims{}
		},
		IdentityHandler: func(c *gin.Context) interface{} {
			claims := jwt.ExtractClaims(c)
			return &User{
				Role: claims[identityKey].(string),
			}
		},
		Authenticator: func(c *gin.Context) (interface{}, error) {
			var loginVals login
			err := c.ShouldBindJSON(&loginVals)
			if err != nil {
				return "", jwt.ErrMissingLoginValues
			}
			username := loginVals.Username
			password := loginVals.Password

			// compare hashed password
			realPassword := database.SelectUser(username)
			if utils.GenHash(password) == realPassword {
				return &User{
					UserName: username,
					// only have one role for now
					Role:    "admin",
					Email:   username,
					IsAdmin: true,
				}, nil
			}

			return nil, jwt.ErrFailedAuthentication
		},
		Authorizator: func(data interface{}, c *gin.Context) bool {
			// @TODO: Disable authorization for now
			if v, ok := data.(*User); ok && v.Role == "admin" {
				return true
			}
			return false
			// return true
		},
		Unauthorized: func(c *gin.Context, code int, message string) {
			c.JSON(code, gin.H{
				"code":    code,
				"message": message,
			})
		},
		TokenLookup:   "header: Authorization, query: token, cookie: jwt",
		TokenHeadName: "Jaeles",
		TimeFunc:      time.Now,
	})

	if err != nil {
		log.Fatal("JWT Error:" + err.Error())
	}

	r.POST("/auth/login", authMiddleware.LoginHandler)
	r.NoRoute(authMiddleware.MiddlewareFunc(), func(c *gin.Context) {
		claims := jwt.ExtractClaims(c)
		utils.InforF("NoRoute claims: %#v\n", claims)
		c.JSON(404, gin.H{"code": "404", "message": "Page not found"})
	})
	auth := r.Group("/api")

	// Refresh time can be longer than token timeout
	auth.GET("/refresh_token", authMiddleware.RefreshHandler)
	if !options.Server.NoAuth {
		auth.Use(authMiddleware.MiddlewareFunc())
	}
	{
		auth.GET("/ping", Ping)
		auth.POST("/parse", ReceiveRequest(result))
		auth.POST("/config/sign", UpdateDefaultSign)
		auth.GET("/stats/vuln", GetStats)
		auth.GET("/stats/sign", GetSignSummary)
		auth.GET("/signatures", GetSigns)
		auth.GET("/scans", GetAllScan)
		auth.GET("/scan/:sid/", GetRecords)
		auth.GET("/record/:rid/", GetRecord)
	}

	if err := http.ListenAndServe(options.Server.Bind, r); err != nil {
		log.Fatal(err)
	}

}
