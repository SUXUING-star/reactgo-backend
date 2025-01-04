package main

import (
	"time"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson/primitive"
)

// 云存储配置
type CloudStorage struct {
	AccessKeyID     string
	AccessKeySecret string
	Endpoint        string
	BucketName      string
	client          *oss.Client
	bucket          *oss.Bucket
}

type CommentWithPost struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"_id"`
	PostID    primitive.ObjectID `bson:"post_id" json:"post_id"`
	Content   string             `bson:"content" json:"content"`
	AuthorID  primitive.ObjectID `bson:"author_id" json:"author_id"`
	Author    string             `bson:"author" json:"author"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
	Post      PostInfo           `json:"post" bson:"post"`
}

type PostInfo struct {
	Title string `json:"title" bson:"title"`
}

type User struct {
	ID             primitive.ObjectID `bson:"_id,omitempty" json:"id"`
	Username       string             `bson:"username" json:"username"`
	Password       string             `bson:"password" json:"password"`
	Email          string             `bson:"email" json:"email"`
	IsVerified     bool               `bson:"is_verified" json:"is_verified"`
	VerifyToken    string             `bson:"verify_token" json:"verify_token"`
	TokenExpiredAt time.Time          `bson:"token_expired_at" json:"token_expired_at"`
	CreatedAt      time.Time          `bson:"created_at" json:"created_at"`
	Post           PostInfo           `json:"post"`
}

type Claims struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

type EmailConfig struct {
	From     string
	AuthCode string
	SmtpHost string
	SmtpPort string
}

type Post struct {
	ID            primitive.ObjectID `bson:"_id,omitempty" json:"_id"`
	Title         string             `bson:"title" json:"title"`
	Content       string             `bson:"content" json:"content"`
	Category      string             `bson:"category" json:"category"`
	TopicID       primitive.ObjectID `bson:"topic_id,omitempty" json:"topic_id,omitempty"`
	Topic         *Topic             `bson:"topic,omitempty" json:"topic,omitempty"`
	AuthorID      primitive.ObjectID `bson:"author_id" json:"author_id"`
	Author        string             `bson:"author" json:"author"`
	CreatedAt     time.Time          `bson:"created_at" json:"created_at"`
	CommentsCount int                `bson:"comments_count" json:"comments_count"`
	ImageURL      string             `bson:"image_url" json:"imageURL"`
}

type Comment struct {
	ID        primitive.ObjectID   `bson:"_id,omitempty" json:"_id"`
	PostID    primitive.ObjectID   `bson:"post_id" json:"post_id"`
	Content   string               `bson:"content" json:"content"`
	AuthorID  primitive.ObjectID   `bson:"author_id" json:"author_id"`
	Author    string               `bson:"author" json:"author"`
	CreatedAt time.Time            `bson:"created_at" json:"created_at"`
	ParentID  primitive.ObjectID   `bson:"parent_id,omitempty" json:"parent_id,omitempty"`
	Likes     []primitive.ObjectID `bson:"likes,omitempty" json:"likes,omitempty"`
	Replies   []Comment            `bson:"replies,omitempty" json:"replies"`
}

type Topic struct {
	ID          primitive.ObjectID   `bson:"_id,omitempty" json:"_id"`
	Title       string               `bson:"title" json:"title"`
	Description string               `bson:"description" json:"description"`
	Posts       []primitive.ObjectID `bson:"posts" json:"posts"`
	CreatedBy   primitive.ObjectID   `bson:"created_by" json:"created_by"`
	CreatedAt   time.Time            `bson:"created_at" json:"created_at"`
}

type Notification struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"_id"`
	UserID    primitive.ObjectID `bson:"user_id" json:"user_id"`
	Type      string             `bson:"type" json:"type"`
	Content   string             `bson:"content" json:"content"`
	PostID    primitive.ObjectID `bson:"post_id" json:"post_id"`
	CommentID primitive.ObjectID `bson:"comment_id,omitempty" json:"comment_id,omitempty"`
	IsRead    bool               `bson:"is_read" json:"is_read"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}

type SearchResult struct {
	Posts  []SearchPost `json:"posts"`
	Topics []Topic      `json:"topics"`
	Users  []UserInfo   `json:"users"`
}

type Message struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"_id"`
	FromID    primitive.ObjectID `bson:"from_id" json:"from_id"`
	ToID      primitive.ObjectID `bson:"to_id" json:"to_id"`
	Content   string             `bson:"content" json:"content"`
	IsRead    bool               `bson:"is_read" json:"is_read"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}

type SearchPost struct {
	ID            primitive.ObjectID `bson:"_id,omitempty" json:"_id"`
	Title         string             `bson:"title" json:"title"`
	Content       string             `bson:"content" json:"content"`
	Author        string             `bson:"author" json:"author"`
	CreatedAt     time.Time          `bson:"created_at" json:"created_at"`
	ImageURL      string             `bson:"image_url" json:"imageURL"`
	CommentsCount int                `bson:"comments_count" json:"comments_count"`
	LikeCount     int                `bson:"like_count" json:"like_count"`
	Tags          []string           `bson:"tags" json:"tags"`
}
type UserInfo struct {
	ID       primitive.ObjectID `bson:"_id" json:"_id"`
	Username string             `bson:"username" json:"username"`
	Avatar   string             `bson:"avatar" json:"avatar"`
	Bio      string             `bson:"bio" json:"bio"`
}
