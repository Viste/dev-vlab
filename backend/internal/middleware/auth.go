package middleware

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

type Claims struct {
	UserID  uint `json:"user_id"`
	IsAdmin bool `json:"is_admin"`
	jwt.RegisteredClaims
}

type UserChecker func(id uint) (isAdmin bool, ok bool)

var (
	errNoHeader      = errors.New("authorization header required")
	errInvalidHeader = errors.New("invalid authorization header")
	errInvalidToken  = errors.New("invalid token")
)

func parseClaims(c *gin.Context, secret string) (*Claims, error) {
	header := c.GetHeader("Authorization")
	if header == "" {
		return nil, errNoHeader
	}

	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 || parts[0] != "Bearer" {
		return nil, errInvalidHeader
	}

	claims := &Claims{}
	token, err := jwt.ParseWithClaims(parts[1], claims, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil || !token.Valid {
		return nil, errInvalidToken
	}
	return claims, nil
}

func resolve(claims *Claims, check UserChecker) (isAdmin bool, ok bool) {
	if check == nil {
		return claims.IsAdmin, true
	}
	return check(claims.UserID)
}

func JWTAuth(secret string, check UserChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := parseClaims(c, secret)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": err.Error()})
			return
		}

		isAdmin, ok := resolve(claims, check)
		if !ok {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "account disabled"})
			return
		}

		c.Set("user_id", claims.UserID)
		c.Set("is_admin", isAdmin)
		c.Next()
	}
}

// OptionalAuth extracts user info if token present, but doesn't block
func OptionalAuth(secret string, check UserChecker) gin.HandlerFunc {
	return func(c *gin.Context) {
		claims, err := parseClaims(c, secret)
		if err == nil {
			if isAdmin, ok := resolve(claims, check); ok {
				c.Set("user_id", claims.UserID)
				c.Set("is_admin", isAdmin)
			}
		}
		c.Next()
	}
}

func AdminOnly() gin.HandlerFunc {
	return func(c *gin.Context) {
		isAdmin, exists := c.Get("is_admin")
		if !exists || !isAdmin.(bool) {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "admin access required"})
			return
		}
		c.Next()
	}
}

func GetUserID(c *gin.Context) (uint, bool) {
	id, exists := c.Get("user_id")
	if !exists {
		return 0, false
	}
	return id.(uint), true
}
