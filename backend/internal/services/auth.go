package services

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"

	"dev-vlab/internal/config"
	"dev-vlab/internal/middleware"
	"dev-vlab/internal/models"
	"dev-vlab/internal/repository"

	"github.com/golang-jwt/jwt/v5"
	"github.com/redis/go-redis/v9"
)

type AuthService struct {
	cfg   *config.Config
	repo  *repository.Repository
	redis *redis.Client
}

func NewAuthService(cfg *config.Config, repo *repository.Repository, redis *redis.Client) *AuthService {
	return &AuthService{cfg: cfg, repo: repo, redis: redis}
}

func (s *AuthService) GetRepo() *repository.Repository {
	return s.repo
}

func (s *AuthService) GenerateJWT(user *models.User) (string, error) {
	claims := &middleware.Claims{
		UserID:  user.ID,
		IsAdmin: user.IsAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(s.cfg.JWTExpires)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.cfg.JWTSecret))
}

// --- VK OAuth PKCE ---

func (s *AuthService) VKAuthURL() (string, error) {
	ctx := context.Background()

	codeVerifier := generateRandomString(64)
	state := generateRandomString(32)

	h := sha256.Sum256([]byte(codeVerifier))
	codeChallenge := base64.RawURLEncoding.EncodeToString(h[:])

	key := fmt.Sprintf("vk_oauth:%s", state)
	s.redis.Set(ctx, key, codeVerifier, 15*time.Minute)

	params := url.Values{
		"client_id":             {s.cfg.VKClientID},
		"redirect_uri":         {s.cfg.VKRedirectURI},
		"response_type":        {"code"},
		"scope":                {"email"},
		"state":                {state},
		"code_challenge":       {codeChallenge},
		"code_challenge_method": {"S256"},
	}

	return "https://id.vk.com/authorize?" + params.Encode(), nil
}

func (s *AuthService) VKCallback(code, state, deviceID string) (*models.User, error) {
	ctx := context.Background()

	key := fmt.Sprintf("vk_oauth:%s", state)
	codeVerifier, err := s.redis.Get(ctx, key).Result()
	if err != nil {
		return nil, fmt.Errorf("invalid or expired state")
	}
	s.redis.Del(ctx, key)

	tokenData := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"client_id":     {s.cfg.VKClientID},
		"redirect_uri":  {s.cfg.VKRedirectURI},
		"code_verifier": {codeVerifier},
		"device_id":     {deviceID},
	}

	resp, err := http.PostForm("https://id.vk.com/oauth2/auth", tokenData)
	if err != nil {
		return nil, fmt.Errorf("vk token exchange failed: %w", err)
	}
	defer resp.Body.Close()

	var tokenResp struct {
		AccessToken string `json:"access_token"`
		UserID      int    `json:"user_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return nil, fmt.Errorf("failed to decode vk token response: %w", err)
	}

	if tokenResp.AccessToken == "" {
		return nil, fmt.Errorf("vk returned empty access token")
	}

	infoData := url.Values{
		"access_token": {tokenResp.AccessToken},
		"client_id":    {s.cfg.VKClientID},
	}

	infoResp, err := http.PostForm("https://id.vk.com/oauth2/user_info", infoData)
	if err != nil {
		return nil, fmt.Errorf("vk user info request failed: %w", err)
	}
	defer infoResp.Body.Close()

	var userInfo struct {
		User struct {
			FirstName string `json:"first_name"`
			LastName  string `json:"last_name"`
			Email     string `json:"email"`
			Avatar    string `json:"avatar"`
		} `json:"user"`
	}
	if err := json.NewDecoder(infoResp.Body).Decode(&userInfo); err != nil {
		return nil, fmt.Errorf("failed to decode vk user info: %w", err)
	}

	vkID := fmt.Sprintf("%d", tokenResp.UserID)

	user, err := s.repo.GetUserByVKID(vkID)
	if err != nil {
		username := fmt.Sprintf("vk_%d", tokenResp.UserID)
		user = &models.User{
			Username:       username,
			VKID:           vkID,
			FirstName:      userInfo.User.FirstName,
			LastName:       userInfo.User.LastName,
			Email:          userInfo.User.Email,
			ProfilePicture: userInfo.User.Avatar,
			Provider:       "vk",
		}
		if err := s.repo.CreateUser(user); err != nil {
			return nil, fmt.Errorf("failed to create user: %w", err)
		}
	}

	return user, nil
}

// --- Telegram OAuth ---

type TelegramAuthData struct {
	ID        int64  `json:"id"`
	FirstName string `json:"first_name"`
	LastName  string `json:"last_name"`
	Username  string `json:"username"`
	PhotoURL  string `json:"photo_url"`
	AuthDate  int64  `json:"auth_date"`
	Hash      string `json:"hash"`
}

func (s *AuthService) TelegramCallback(data TelegramAuthData) (*models.User, error) {
	if !s.verifyTelegramAuth(data) {
		return nil, fmt.Errorf("invalid telegram auth data")
	}

	tgID := fmt.Sprintf("%d", data.ID)

	user, err := s.repo.GetUserByTelegramID(tgID)
	if err != nil {
		username := data.Username
		if username == "" {
			username = fmt.Sprintf("tg_%d", data.ID)
		}
		user = &models.User{
			Username:       username,
			TelegramID:     tgID,
			FirstName:      data.FirstName,
			LastName:       data.LastName,
			ProfilePicture: data.PhotoURL,
			Provider:       "telegram",
		}
		if err := s.repo.CreateUser(user); err != nil {
			return nil, fmt.Errorf("failed to create user: %w", err)
		}
	}

	return user, nil
}

func (s *AuthService) verifyTelegramAuth(data TelegramAuthData) bool {
	if s.cfg.TelegramBotToken == "" {
		return false
	}

	if time.Now().Unix()-data.AuthDate > 86400 {
		return false
	}

	checkStrings := []string{}

	if data.AuthDate > 0 {
		checkStrings = append(checkStrings, fmt.Sprintf("auth_date=%d", data.AuthDate))
	}
	if data.FirstName != "" {
		checkStrings = append(checkStrings, fmt.Sprintf("first_name=%s", data.FirstName))
	}
	if data.ID > 0 {
		checkStrings = append(checkStrings, fmt.Sprintf("id=%d", data.ID))
	}
	if data.LastName != "" {
		checkStrings = append(checkStrings, fmt.Sprintf("last_name=%s", data.LastName))
	}
	if data.PhotoURL != "" {
		checkStrings = append(checkStrings, fmt.Sprintf("photo_url=%s", data.PhotoURL))
	}
	if data.Username != "" {
		checkStrings = append(checkStrings, fmt.Sprintf("username=%s", data.Username))
	}

	dataCheckString := strings.Join(checkStrings, "\n")

	secretKey := sha256.Sum256([]byte(s.cfg.TelegramBotToken))

	mac := hmacSHA256([]byte(dataCheckString), secretKey[:])
	expectedHash := fmt.Sprintf("%x", mac)

	return expectedHash == data.Hash
}

func generateRandomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
