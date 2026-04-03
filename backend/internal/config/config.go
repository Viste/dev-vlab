package config

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/joho/godotenv"
)

type Config struct {
	Port string
	Env  string

	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
	DBSSLMode  string

	RedisAddr     string
	RedisPassword string
	RedisDB       int

	JWTSecret  string
	JWTExpires time.Duration

	VKClientID     string
	VKClientSecret string
	VKRedirectURI  string

	TelegramBotToken  string
	TelegramBotSecret string

	CORSOrigins []string

	UploadDir string
	StaticDir string

	FrontendURL string
}

func Load() *Config {
	godotenv.Load()

	return &Config{
		Port: getEnv("PORT", "8000"),
		Env:  getEnv("ENV", "development"),

		DBHost:     getEnv("DB_HOST", "localhost"),
		DBPort:     getEnv("DB_PORT", "5432"),
		DBUser:     getEnv("DB_USER", "viste"),
		DBPassword: getEnv("DB_PASSWORD", ""),
		DBName:     getEnv("DB_NAME", "vlab"),
		DBSSLMode:  getEnv("DB_SSLMODE", "disable"),

		RedisAddr:     getEnv("REDIS_ADDR", "localhost:6379"),
		RedisPassword: getEnv("REDIS_PASSWORD", ""),
		RedisDB:       getEnvAsInt("REDIS_DB", 0),

		JWTSecret:  getEnv("JWT_SECRET", "change-me-in-production"),
		JWTExpires: time.Duration(getEnvAsInt("JWT_EXPIRATION_HOURS", 72)) * time.Hour,

		VKClientID:     getEnv("VK_CLIENT_ID", ""),
		VKClientSecret: getEnv("VK_CLIENT_SECRET", ""),
		VKRedirectURI:  getEnv("VK_REDIRECT_URI", ""),

		TelegramBotToken:  getEnv("TELEGRAM_BOT_TOKEN", ""),
		TelegramBotSecret: getEnv("TELEGRAM_BOT_SECRET", ""),

		CORSOrigins: []string{
			getEnv("CORS_ORIGIN", "http://localhost:5173"),
			"https://dev-vlab.ru",
		},

		UploadDir:   getEnv("UPLOAD_DIR", "./uploads"),
		StaticDir:   getEnv("STATIC_DIR", ""),
		FrontendURL: getEnv("FRONTEND_URL", "http://localhost:5173"),
	}
}

func (c *Config) DSN() string {
	return fmt.Sprintf("host=%s user=%s password=%s dbname=%s port=%s sslmode=%s",
		c.DBHost, c.DBUser, c.DBPassword, c.DBName, c.DBPort, c.DBSSLMode)
}

func getEnv(key, fallback string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return fallback
}

func getEnvAsInt(key string, fallback int) int {
	if val, ok := os.LookupEnv(key); ok {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return fallback
}
