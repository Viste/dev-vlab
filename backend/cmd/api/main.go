package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"dev-vlab/internal/config"
	"dev-vlab/internal/handlers"
	"dev-vlab/internal/middleware"
	"dev-vlab/internal/models"
	"dev-vlab/internal/repository"
	"dev-vlab/internal/services"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func main() {
	cfg := config.Load()

	gormLogLevel := logger.Warn
	if cfg.Env != "production" {
		gormLogLevel = logger.Info
	}
	db, err := gorm.Open(postgres.New(postgres.Config{
		DSN:                  cfg.DSN(),
		PreferSimpleProtocol: true,
	}), &gorm.Config{
		Logger:                                   logger.Default.LogMode(gormLogLevel),
		PrepareStmt:                              false,
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	sqlDB, _ := db.DB()
	sqlDB.SetMaxOpenConns(20)
	sqlDB.SetMaxIdleConns(5)
	sqlDB.SetConnMaxLifetime(time.Hour)

	db.Exec(`ALTER TABLE "user" DROP CONSTRAINT IF EXISTS user_username_key`)
	db.Exec(`ALTER TABLE "user" DROP CONSTRAINT IF EXISTS user_email_key`)
	db.Exec(`ALTER TABLE "user" DROP CONSTRAINT IF EXISTS user_telegram_id_key`)
	db.Exec(`ALTER TABLE "user" DROP CONSTRAINT IF EXISTS user_vk_id_key`)
	db.Exec(`ALTER TABLE "user" DROP CONSTRAINT IF EXISTS uni_user_username`)
	db.Exec(`ALTER TABLE "user" DROP CONSTRAINT IF EXISTS uni_user_email`)

	if err := db.AutoMigrate(
		&models.User{},
		&models.BlogPost{},
		&models.Comment{},
		&models.MusicRelease{},
		&models.MusicDemo{},
		&models.RadioStream{},
		&models.Project{},
		&models.NavigationLink{},
	); err != nil {
		log.Printf("warning: auto-migrate: %v", err)
	}

	rdb := redis.NewClient(&redis.Options{
		Addr:     cfg.RedisAddr,
		Password: cfg.RedisPassword,
		DB:       cfg.RedisDB,
	})
	if err := rdb.Ping(context.Background()).Err(); err != nil {
		log.Printf("warning: redis not available: %v", err)
	}

	repo := repository.New(db)
	authService := services.NewAuthService(cfg, repo, rdb)

	saturatorHandler := handlers.NewSaturatorHandler(rdb)
	authHandler := handlers.NewAuthHandler(authService)
	blogHandler := handlers.NewBlogHandler(repo)
	musicHandler := handlers.NewMusicHandler(repo)
	projectHandler := handlers.NewProjectHandler(repo)
	userHandler := handlers.NewUserHandler(repo, authService)
	navLinkHandler := handlers.NewNavLinkHandler(repo)

	if cfg.Env == "production" {
		gin.SetMode(gin.ReleaseMode)
	}
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     cfg.CORSOrigins,
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
		MaxAge:           5 * time.Minute,
	}))

	r.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	api := r.Group("/api")
	{
		auth := api.Group("/auth")
		{
			auth.POST("/login", authHandler.Login)
			auth.GET("/vk", authHandler.VKLogin)
			auth.POST("/vk/callback", authHandler.VKCallback)
			auth.POST("/telegram/callback", authHandler.TelegramCallback)
			auth.GET("/me", middleware.JWTAuth(cfg.JWTSecret), authHandler.Me)
		}

		blog := api.Group("/blog")
		blog.Use(middleware.OptionalAuth(cfg.JWTSecret))
		{
			blog.GET("", blogHandler.ListPosts)
			blog.GET("/:slug", blogHandler.GetPost)
			blog.POST("/:slug/comments", middleware.JWTAuth(cfg.JWTSecret), blogHandler.AddComment)
			blog.DELETE("/comments/:id", middleware.JWTAuth(cfg.JWTSecret), blogHandler.DeleteComment)
		}

		music := api.Group("/music")
		{
			music.GET("/releases", musicHandler.ListReleases)
			music.GET("/demos", musicHandler.ListDemos)
			music.GET("/radio", musicHandler.GetRadio)
		}

		api.GET("/projects", projectHandler.List)

		api.GET("/nav-links", navLinkHandler.List)

		api.GET("/saturator/version", saturatorHandler.GetVersion)

		user := api.Group("/user")
		user.Use(middleware.JWTAuth(cfg.JWTSecret))
		{
			user.GET("/profile", userHandler.GetProfile)
			user.PUT("/profile", userHandler.UpdateProfile)
			user.PUT("/password", userHandler.ChangePassword)
			user.POST("/avatar", userHandler.UploadAvatar)
		}

		admin := api.Group("/admin")
		admin.Use(middleware.JWTAuth(cfg.JWTSecret), middleware.AdminOnly())
		{
			admin.GET("/blog", blogHandler.AdminListPosts)
			admin.POST("/blog", blogHandler.AdminCreatePost)
			admin.PUT("/blog/:id", blogHandler.AdminUpdatePost)
			admin.DELETE("/blog/:id", blogHandler.AdminDeletePost)

			admin.POST("/music/releases", musicHandler.AdminCreateRelease)
			admin.PUT("/music/releases/:id", musicHandler.AdminUpdateRelease)
			admin.DELETE("/music/releases/:id", musicHandler.AdminDeleteRelease)

			admin.POST("/music/demos", musicHandler.AdminCreateDemo)
			admin.PUT("/music/demos/:id", musicHandler.AdminUpdateDemo)
			admin.DELETE("/music/demos/:id", musicHandler.AdminDeleteDemo)

			admin.POST("/music/radio", musicHandler.AdminCreateRadio)
			admin.PUT("/music/radio/:id", musicHandler.AdminUpdateRadio)
			admin.DELETE("/music/radio/:id", musicHandler.AdminDeleteRadio)

			admin.POST("/projects", projectHandler.AdminCreate)
			admin.PUT("/projects/:id", projectHandler.AdminUpdate)
			admin.DELETE("/projects/:id", projectHandler.AdminDelete)

			admin.GET("/nav-links", navLinkHandler.AdminList)
			admin.POST("/nav-links", navLinkHandler.AdminCreate)
			admin.PUT("/nav-links/:id", navLinkHandler.AdminUpdate)
			admin.DELETE("/nav-links/:id", navLinkHandler.AdminDelete)
		}
	}

	r.Static("/uploads", cfg.UploadDir)

	if cfg.StaticDir != "" {
		r.Static("/assets", cfg.StaticDir+"/assets")
		r.GET("/favicon.svg", func(c *gin.Context) {
			c.File(cfg.StaticDir + "/favicon.svg")
		})
		r.GET("/favicon.ico", func(c *gin.Context) {
			c.File(cfg.StaticDir + "/favicon.ico")
		})
		r.NoRoute(func(c *gin.Context) {
			c.File(cfg.StaticDir + "/index.html")
		})
	}

	srv := &http.Server{
		Addr:    ":" + cfg.Port,
		Handler: r,
	}

	go func() {
		log.Printf("server starting on :%s", cfg.Port)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit

	log.Println("shutting down...")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	srv.Shutdown(ctx)
}
