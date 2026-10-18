package models

import (
	"time"

	"gorm.io/gorm"
)

func (User) TableName() string { return "user" }

type User struct {
	ID             uint           `json:"id" gorm:"primaryKey"`
	Username       string         `json:"username" gorm:"uniqueIndex;size:64;not null"`
	Email          string         `json:"email,omitempty" gorm:"size:255"`
	PasswordHash   string         `json:"-" gorm:"size:255"`
	FirstName      string         `json:"first_name,omitempty" gorm:"size:64"`
	LastName       string         `json:"last_name,omitempty" gorm:"size:64"`
	ProfilePicture string         `json:"profile_picture,omitempty" gorm:"size:255"`
	TelegramID     string         `json:"telegram_id,omitempty" gorm:"size:64;index"`
	VKID           string         `json:"vk_id,omitempty" gorm:"size:64;index"`
	Provider       string         `json:"provider,omitempty" gorm:"size:32"`
	IsAdmin        bool           `json:"is_admin" gorm:"default:false"`
	IsBanned       bool           `json:"is_banned" gorm:"default:false"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
	DeletedAt      gorm.DeletedAt `json:"-" gorm:"index"`

	Comments []Comment `json:"-" gorm:"foreignKey:UserID"`
}

type BlogPost struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	Title     string         `json:"title" gorm:"size:255;not null"`
	Slug      string         `json:"slug" gorm:"size:255;not null"`
	Content   string         `json:"content" gorm:"type:text;not null"`
	Summary   string         `json:"summary,omitempty" gorm:"size:512"`
	CoverURL  string         `json:"cover_url,omitempty" gorm:"size:255"`
	Published bool           `json:"published" gorm:"default:false"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`

	Comments []Comment `json:"comments,omitempty" gorm:"foreignKey:PostID"`
}

type Comment struct {
	ID        uint           `json:"id" gorm:"primaryKey"`
	PostID    uint           `json:"post_id" gorm:"index;not null"`
	UserID    uint           `json:"user_id" gorm:"index;not null"`
	Content   string         `json:"content" gorm:"type:text;not null"`
	CreatedAt time.Time      `json:"created_at"`
	DeletedAt gorm.DeletedAt `json:"-" gorm:"index"`

	User User `json:"user" gorm:"foreignKey:UserID"`
}

type MusicRelease struct {
	ID          uint           `json:"id" gorm:"primaryKey"`
	Title       string         `json:"title" gorm:"size:255;not null"`
	Artist      string         `json:"artist,omitempty" gorm:"size:255"`
	CoverURL    string         `json:"cover_url,omitempty" gorm:"size:512"`
	ReleaseURL  string         `json:"release_url,omitempty" gorm:"size:512"`
	EmbedURL    string         `json:"embed_url,omitempty" gorm:"size:512"`
	ReleaseDate *time.Time     `json:"release_date,omitempty"`
	SortOrder   int            `json:"sort_order" gorm:"default:0"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`
}

type MusicDemo struct {
	ID          uint           `json:"id" gorm:"primaryKey"`
	Title       string         `json:"title" gorm:"size:255;not null"`
	Description string         `json:"description,omitempty" gorm:"type:text"`
	FileURL     string         `json:"file_url,omitempty" gorm:"size:512"`
	EmbedURL    string         `json:"embed_url,omitempty" gorm:"size:512"`
	SortOrder   int            `json:"sort_order" gorm:"default:0"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`
}

type RadioStream struct {
	ID        uint      `json:"id" gorm:"primaryKey"`
	Title     string    `json:"title" gorm:"size:255;not null"`
	StreamURL string    `json:"stream_url" gorm:"size:512;not null"`
	IsActive  bool      `json:"is_active" gorm:"default:true"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Project struct {
	ID          uint           `json:"id" gorm:"primaryKey"`
	Title       string         `json:"title" gorm:"size:255;not null"`
	Description string         `json:"description,omitempty" gorm:"type:text"`
	ImageURL    string         `json:"image_url,omitempty" gorm:"size:512"`
	ProjectURL  string         `json:"project_url,omitempty" gorm:"size:512"`
	SortOrder   int            `json:"sort_order" gorm:"default:0"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`
}

type NavigationLink struct {
	ID        uint   `json:"id" gorm:"primaryKey"`
	Title     string `json:"title" gorm:"size:128;not null"`
	URL       string `json:"url" gorm:"size:512;not null"`
	Icon      string `json:"icon,omitempty" gorm:"size:64"`
	SortOrder int    `json:"sort_order" gorm:"default:0"`
	IsActive  bool   `json:"is_active" gorm:"default:true"`
}

const (
	ApartmentStatusNew       = "new"
	ApartmentStatusScheduled = "scheduled"
	ApartmentStatusVisited   = "visited"
	ApartmentStatusShortlist = "shortlist"
	ApartmentStatusRejected  = "rejected"
)

var ApartmentStatuses = []string{
	ApartmentStatusNew,
	ApartmentStatusScheduled,
	ApartmentStatusVisited,
	ApartmentStatusShortlist,
	ApartmentStatusRejected,
}

func IsValidApartmentStatus(s string) bool {
	for _, v := range ApartmentStatuses {
		if v == s {
			return true
		}
	}
	return false
}

type Apartment struct {
	ID          uint           `json:"id" gorm:"primaryKey"`
	URL         string         `json:"url" gorm:"size:1024;not null"`
	Source      string         `json:"source" gorm:"size:32;index"`
	Title       string         `json:"title" gorm:"size:255"`
	Address     string         `json:"address,omitempty" gorm:"size:512"`
	Price       int64          `json:"price" gorm:"default:0"`
	Rooms       int            `json:"rooms" gorm:"default:0"`
	Area        float64        `json:"area" gorm:"default:0"`
	Floor       int            `json:"floor" gorm:"default:0"`
	TotalFloors int            `json:"total_floors" gorm:"default:0"`
	Notes       string         `json:"notes,omitempty" gorm:"type:text"`
	Status      string         `json:"status" gorm:"size:32;default:'new';index"`
	CreatedBy   uint           `json:"created_by" gorm:"index"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`
	DeletedAt   gorm.DeletedAt `json:"-" gorm:"index"`

	Creator *User             `json:"creator,omitempty" gorm:"foreignKey:CreatedBy"`
	Ratings []ApartmentRating `json:"ratings" gorm:"foreignKey:ApartmentID"`

	Score float64 `json:"score" gorm:"-"`
}

type ApartmentRating struct {
	ID          uint           `json:"id" gorm:"primaryKey"`
	ApartmentID uint           `json:"apartment_id" gorm:"uniqueIndex:idx_apartment_rating_user;not null"`
	UserID      uint           `json:"user_id" gorm:"uniqueIndex:idx_apartment_rating_user;not null"`
	Scores      map[string]int `json:"scores" gorm:"type:text;serializer:json"`
	Comment     string         `json:"comment,omitempty" gorm:"type:text"`
	CreatedAt   time.Time      `json:"created_at"`
	UpdatedAt   time.Time      `json:"updated_at"`

	User *User `json:"user,omitempty" gorm:"foreignKey:UserID"`

	Score float64 `json:"score" gorm:"-"`
}

func (ApartmentCriterion) TableName() string { return "apartment_criteria" }

type ApartmentCriterion struct {
	ID        uint    `json:"id" gorm:"primaryKey"`
	Key       string  `json:"key" gorm:"size:64;uniqueIndex;not null"`
	LabelEn   string  `json:"label_en" gorm:"size:128"`
	LabelRu   string  `json:"label_ru" gorm:"size:128"`
	Weight    float64 `json:"weight" gorm:"default:1"`
	SortOrder int     `json:"sort_order" gorm:"default:0"`
	IsActive  bool    `json:"is_active" gorm:"default:true"`
}

var DefaultApartmentCriteria = []ApartmentCriterion{
	{Key: "location", LabelEn: "Location & district", LabelRu: "Расположение и район", Weight: 1.5, SortOrder: 1, IsActive: true},
	{Key: "price", LabelEn: "Price / value", LabelRu: "Цена / выгода", Weight: 1.5, SortOrder: 2, IsActive: true},
	{Key: "layout", LabelEn: "Layout", LabelRu: "Планировка", Weight: 1, SortOrder: 3, IsActive: true},
	{Key: "condition", LabelEn: "Condition & renovation", LabelRu: "Состояние и ремонт", Weight: 1, SortOrder: 4, IsActive: true},
	{Key: "transport", LabelEn: "Transport & metro", LabelRu: "Транспорт и метро", Weight: 1, SortOrder: 5, IsActive: true},
	{Key: "infrastructure", LabelEn: "Shops, parks, infrastructure", LabelRu: "Магазины, парки, инфраструктура", Weight: 1, SortOrder: 6, IsActive: true},
	{Key: "building", LabelEn: "Building & entrance", LabelRu: "Дом и подъезд", Weight: 1, SortOrder: 7, IsActive: true},
	{Key: "view", LabelEn: "View, light & noise", LabelRu: "Вид, свет и шум", Weight: 1, SortOrder: 8, IsActive: true},
}
