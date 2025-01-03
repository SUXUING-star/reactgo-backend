package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"math"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
)

var client *mongo.Client
var jwtSecret = []byte(os.Getenv("JWT_SECRET")) // 使用全局变量，并初始化

// 云存储配置
type CloudStorage struct {
	AccessKeyID     string
	AccessKeySecret string
	Endpoint        string
	BucketName      string
	client          *oss.Client
	bucket          *oss.Bucket
}

var cloudStorage *CloudStorage

// 在文件顶部其他结构体定义的地方添加
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
	VerifyToken    string             `bson:"verify_token" json:"verify_token"` // Make sure this field exists
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

var emailConfig EmailConfig

type Post struct {
	ID            primitive.ObjectID `bson:"_id,omitempty" json:"_id"`
	Title         string             `bson:"title" json:"title"`
	Content       string             `bson:"content" json:"content"`
	Category      string             `bson:"category" json:"category"`
	TopicID       primitive.ObjectID `bson:"topic_id,omitempty" json:"topic_id,omitempty"`
	Topic         *Topic             `bson:"topic,omitempty" json:"topic,omitempty"` // 添加话题信息
	AuthorID      primitive.ObjectID `bson:"author_id" json:"author_id"`
	Author        string             `bson:"author" json:"author"`
	CreatedAt     time.Time          `bson:"created_at" json:"created_at"`
	CommentsCount int                `bson:"comments_count" json:"comments_count"`
	ImageURL      string             `bson:"image_url" json:"imageURL"`
}

// 修改 Comment 结构体，保留其他字段不变
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

// 数据模型
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
	Type      string             `bson:"type" json:"type"` // comment, like, reply, etc.
	Content   string             `bson:"content" json:"content"`
	PostID    primitive.ObjectID `bson:"post_id" json:"post_id"`
	IsRead    bool               `bson:"is_read" json:"is_read"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}

// 搜索相关数据结构
type SearchResult struct {
	Posts  []SearchPost `json:"posts"`
	Topics []Topic      `json:"topics"`
	Users  []UserInfo   `json:"users"`
}

// 消息相关数据结构
type Message struct {
	ID        primitive.ObjectID `bson:"_id,omitempty" json:"_id"`
	FromID    primitive.ObjectID `bson:"from_id" json:"from_id"`
	ToID      primitive.ObjectID `bson:"to_id" json:"to_id"`
	Content   string             `bson:"content" json:"content"`
	IsRead    bool               `bson:"is_read" json:"is_read"`
	CreatedAt time.Time          `bson:"created_at" json:"created_at"`
}

type SearchPost struct {
	ID           primitive.ObjectID `bson:"_id" json:"_id"`
	Title        string             `bson:"title" json:"title"`
	Content      string             `bson:"content" json:"content"`
	Author       string             `bson:"author" json:"author"`
	CreatedAt    time.Time          `bson:"created_at" json:"created_at"`
	Tags         []string           `bson:"tags" json:"tags"`
	LikeCount    int                `bson:"like_count" json:"like_count"`
	CommentCount int                `bson:"comment_count" json:"comment_count"`
}

type UserInfo struct {
	ID       primitive.ObjectID `bson:"_id" json:"_id"`
	Username string             `bson:"username" json:"username"`
	Avatar   string             `bson:"avatar" json:"avatar"`
	Bio      string             `bson:"bio" json:"bio"`
}

// main.go
func init() {
	if err := godotenv.Load(); err != nil {
		log.Printf("Warning: .env file not found")
	}

	// 设置 JWT 密钥
	secret := os.Getenv("JWT_SECRET")
	if secret == "" {
		log.Println("Warning: JWT_SECRET not set, using default secret key.")
		secret = "defaultsecret"
	}
	jwtSecret = []byte(secret)
	emailConfig = EmailConfig{
		From:     os.Getenv("EMAIL_FROM"),
		AuthCode: os.Getenv("EMAIL_AUTH_CODE"),
		SmtpHost: os.Getenv("EMAIL_SMTP_HOST"),
		SmtpPort: os.Getenv("EMAIL_SMTP_PORT"),
	}
}

// 初始化云存储
// 确保初始化时正确设置了OSS客户端
func initCloudStorage() error {
	// 检查环境变量
	required := []string{"OSS_ACCESS_KEY_ID", "OSS_ACCESS_KEY_SECRET", "OSS_ENDPOINT", "OSS_BUCKET"}
	for _, env := range required {
		if os.Getenv(env) == "" {
			return fmt.Errorf("missing required environment variable: %s", env)
		}
	}

	log.Printf("Initializing OSS client with endpoint: %s, bucket: %s",
		os.Getenv("OSS_ENDPOINT"),
		os.Getenv("OSS_BUCKET"))

	// 创建OSS客户端
	client, err := oss.New(
		os.Getenv("OSS_ENDPOINT"),
		os.Getenv("OSS_ACCESS_KEY_ID"),
		os.Getenv("OSS_ACCESS_KEY_SECRET"),
	)
	if err != nil {
		return fmt.Errorf("failed to create OSS client: %v", err)
	}

	// 获取存储空间
	bucket, err := client.Bucket(os.Getenv("OSS_BUCKET"))
	if err != nil {
		return fmt.Errorf("failed to get bucket: %v", err)
	}

	cloudStorage = &CloudStorage{
		client: client,
		bucket: bucket,
	}

	log.Println("Cloud storage initialized successfully")
	return nil
}

// 修改文件上传处理函数
func HandleFileUpload(c *gin.Context) {
	log.Println("Starting file upload...")
	file, err := c.FormFile("file")
	if err != nil {
		log.Printf("Error getting form file: %v", err)
		c.JSON(400, gin.H{"error": "No file uploaded"})
		return
	}

	// 生成唯一文件名
	filename := time.Now().Format("20060102150405") + "_" + file.Filename
	objectKey := "uploads/" + filename

	// 打开上传的文件
	src, err := file.Open()
	if err != nil {
		log.Printf("Error opening uploaded file: %v", err)
		c.JSON(500, gin.H{"error": "Failed to open file"})
		return
	}
	defer src.Close()

	// 检查 cloudStorage 是否正确初始化
	if cloudStorage == nil || cloudStorage.bucket == nil {
		log.Printf("Error: Storage not initialized")
		c.JSON(500, gin.H{"error": "Storage not initialized"})
		return
	}

	// 上传到阿里云OSS
	err = cloudStorage.bucket.PutObject(objectKey, src)
	if err != nil {
		log.Printf("Error uploading to OSS: %v", err)
		c.JSON(500, gin.H{"error": "Failed to upload file"})
		return
	}

	// 构造正确的访问URL
	bucketName := os.Getenv("OSS_BUCKET")
	cloudURL := fmt.Sprintf("https://%s.%s/%s",
		bucketName,
		"oss-cn-beijing.aliyuncs.com", // 直接使用完整的域名
		objectKey)

	log.Printf("File uploaded successfully. URL: %s", cloudURL)

	// 验证文件是否可访问
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(cloudURL)
	if err != nil {
		log.Printf("Warning: Could not verify uploaded file: %v", err)
	} else {
		resp.Body.Close()
		log.Printf("File verification status: %d", resp.StatusCode)
	}

	c.JSON(200, gin.H{"url": cloudURL})
}

// 迁移现有文件到云存储
// 在数据库中迁移图片URL
func migrateExistingFilesToCloud() {
	log.Println("Starting database image URLs migration...")
	collection := client.Database("forum").Collection("posts")

	// 找到所有包含本地路径的帖子
	cursor, err := collection.Find(context.TODO(), bson.M{
		"imageURL": bson.M{
			"$exists": true,
			"$ne":     "",
			"$regex":  "^/uploads/",
		},
	})
	if err != nil {
		log.Printf("Error finding posts with local images: %v", err)
		return
	}
	defer cursor.Close(context.TODO())

	var posts []Post
	if err = cursor.All(context.TODO(), &posts); err != nil {
		log.Printf("Error decoding posts: %v", err)
		return
	}

	log.Printf("Found %d posts with local image URLs", len(posts))

	for _, post := range posts {
		// 构造阿里云OSS的URL
		filename := filepath.Base(post.ImageURL)
		objectKey := "uploads/" + filename
		cloudURL := fmt.Sprintf("https://%s.%s/%s",
			os.Getenv("OSS_BUCKET"),
			os.Getenv("OSS_ENDPOINT"),
			objectKey)

		// 更新数据库记录
		_, err = collection.UpdateOne(
			context.TODO(),
			bson.M{"_id": post.ID},
			bson.M{"$set": bson.M{"imageURL": cloudURL}},
		)
		if err != nil {
			log.Printf("Error updating post %s: %v", post.ID, err)
			continue
		}

		log.Printf("Updated image URL for post %s: %s -> %s",
			post.ID, post.ImageURL, cloudURL)
	}

	log.Println("Database migration completed")
}
func getCommunityStats(c *gin.Context) {
	var stats struct {
		TotalPosts    int64 `json:"totalPosts"`
		TotalUsers    int64 `json:"totalUsers"`
		TotalComments int64 `json:"totalComments"`
		ActiveUsers   int64 `json:"activeUsers"`
	}

	postsCollection := client.Database("forum").Collection("posts")
	usersCollection := client.Database("forum").Collection("users")
	commentsCollection := client.Database("forum").Collection("comments")

	// Get total posts
	stats.TotalPosts, _ = postsCollection.CountDocuments(context.TODO(), bson.M{})

	// Get total users
	stats.TotalUsers, _ = usersCollection.CountDocuments(context.TODO(), bson.M{})

	// Get total comments
	stats.TotalComments, _ = commentsCollection.CountDocuments(context.TODO(), bson.M{})

	// Get active users (users who posted in last 30 days)
	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
	stats.ActiveUsers, _ = postsCollection.CountDocuments(context.TODO(), bson.M{
		"created_at": bson.M{"$gte": thirtyDaysAgo},
	})

	c.JSON(200, stats)
}

// 获取用户帖子
func getUserPosts(c *gin.Context) {
	userID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		log.Printf("Invalid user ID: %v", err)
		c.JSON(400, gin.H{"error": "Invalid user ID"})
		return
	}

	log.Printf("Fetching posts for user ID: %v", userID)
	collection := client.Database("forum").Collection("posts")

	// 修改查询条件：使用 author_id 而不是 author
	cursor, err := collection.Find(context.TODO(), bson.M{"author_id": userID})
	if err != nil {
		log.Printf("Error fetching posts: %v", err)
		c.JSON(500, gin.H{"error": "Failed to fetch posts"})
		return
	}
	defer cursor.Close(context.TODO())

	var posts []Post
	if err = cursor.All(context.TODO(), &posts); err != nil {
		log.Printf("Error decoding posts: %v", err)
		c.JSON(500, gin.H{"error": "Failed to decode posts"})
		return
	}

	log.Printf("Found %d posts for user %v", len(posts), userID)
	c.JSON(200, posts)
}

func getUserComments(c *gin.Context) {
	userID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		log.Printf("Invalid user ID: %v", err)
		c.JSON(400, gin.H{"error": "Invalid user ID"})
		return
	}

	log.Printf("Fetching comments for user ID: %v", userID)

	collection := client.Database("forum").Collection("comments")

	// 定义聚合管道，使用显式的字段名
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.D{{Key: "author_id", Value: userID}}}},
		{{Key: "$lookup", Value: bson.D{
			{Key: "from", Value: "posts"},
			{Key: "localField", Value: "post_id"},
			{Key: "foreignField", Value: "_id"},
			{Key: "as", Value: "post_info"},
		}}},
		{{Key: "$addFields", Value: bson.D{
			{Key: "post", Value: bson.D{
				{Key: "title", Value: bson.D{
					{Key: "$arrayElemAt", Value: []interface{}{"$post_info.title", 0}},
				}},
			}},
		}}},
		{{Key: "$project", Value: bson.D{
			{Key: "post_info", Value: 0},
		}}},
	}

	cursor, err := collection.Aggregate(context.TODO(), pipeline)
	if err != nil {
		log.Printf("Error fetching comments: %v", err)
		c.JSON(500, gin.H{"error": "Failed to fetch comments"})
		return
	}
	defer cursor.Close(context.TODO())

	var comments []CommentWithPost
	if err = cursor.All(context.TODO(), &comments); err != nil {
		log.Printf("Error decoding comments: %v", err)
		c.JSON(500, gin.H{"error": "Failed to decode comments"})
		return
	}

	log.Printf("Found %d comments", len(comments))
	c.JSON(200, comments)
}

// 更新帖子
func updatePost(c *gin.Context) {
	postID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid post ID"})
		return
	}

	userID, _ := c.Get("user_id")

	// 确认是帖子作者
	collection := client.Database("forum").Collection("posts")
	var existingPost Post
	err = collection.FindOne(context.TODO(), bson.M{
		"_id":       postID,
		"author_id": userID.(primitive.ObjectID),
	}).Decode(&existingPost)
	if err != nil {
		c.JSON(403, gin.H{"error": "Not authorized to update this post"})
		return
	}

	// 修改数据结构，包括 topic_id
	var updateData struct {
		Title    string  `json:"title"`
		Content  string  `json:"content"`
		ImageURL string  `json:"imageURL"`
		TopicID  *string `json:"topic_id"` // topic_id 可能为空，使用 *string
	}
	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}
	update := bson.M{
		"$set": bson.M{
			"title":     updateData.Title,
			"content":   updateData.Content,
			"image_url": updateData.ImageURL,
		},
	}
	// 添加 topic_id 更新
	if updateData.TopicID != nil {
		topicID, err := primitive.ObjectIDFromHex(*updateData.TopicID)
		if err == nil {
			update["$set"].(bson.M)["topic_id"] = topicID
		} else {
			update["$set"].(bson.M)["topic_id"] = nil
		}
	}

	log.Printf("Updating post %s with image URL: %s", postID, updateData.ImageURL)

	_, err = collection.UpdateOne(context.TODO(), bson.M{"_id": postID}, update)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to update post"})
		return
	}

	c.JSON(200, gin.H{"message": "Post updated successfully"})
}

func deletePost(c *gin.Context) {
	postID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		log.Printf("Invalid post ID: %v", err)
		c.JSON(400, gin.H{"error": "Invalid post ID"})
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		log.Printf("User ID not found in context")
		c.JSON(401, gin.H{"error": "User ID not found"})
		return
	}

	username, exists := c.Get("username")
	if !exists {
		log.Printf("Username not found in context")
		c.JSON(401, gin.H{"error": "Username not found"})
		return
	}

	collection := client.Database("forum").Collection("posts")
	commentsCollection := client.Database("forum").Collection("comments")

	// 检查权限
	if username.(string) != "admin" {
		var post Post
		err = collection.FindOne(context.TODO(), bson.M{"_id": postID}).Decode(&post)
		if err != nil {
			c.JSON(404, gin.H{"error": "Post not found"})
			return
		}

		if post.AuthorID != userID.(primitive.ObjectID) {
			c.JSON(403, gin.H{"error": "Not authorized to delete this post"})
			return
		}
	}

	// 删除帖子
	_, err = collection.DeleteOne(context.TODO(), bson.M{"_id": postID})
	if err != nil {
		log.Printf("Error deleting post: %v", err)
		c.JSON(500, gin.H{"error": "Failed to delete post"})
		return
	}

	// 删除所有相关评论
	_, err = commentsCollection.DeleteMany(context.TODO(), bson.M{"post_id": postID})
	if err != nil {
		log.Printf("Error deleting comments: %v", err)
		// 即使删除评论失败，帖子已经删除，所以仍然返回成功
		c.JSON(200, gin.H{"message": "Post deleted but failed to delete some comments"})
		return
	}

	c.JSON(200, gin.H{"message": "Post and all related comments deleted successfully"})
}

// 修改 deleteTopic 函数
func deleteTopic(c *gin.Context) {
	topicID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		log.Printf("Invalid topic ID: %v", err)
		c.JSON(400, gin.H{"error": "Invalid topic ID"})
		return
	}
	userID, exists := c.Get("user_id")
	if !exists {
		log.Printf("User ID not found in context")
		c.JSON(401, gin.H{"error": "User ID not found"})
		return
	}

	username, exists := c.Get("username")
	if !exists {
		log.Printf("Username not found in context")
		c.JSON(401, gin.H{"error": "Username not found"})
		return
	}
	collection := client.Database("forum").Collection("topics")
	postsCollection := client.Database("forum").Collection("posts")

	// 检查用户权限, 如果不是管理员则验证是否是创建者
	if username.(string) != "admin" {
		var topic Topic
		err = collection.FindOne(context.TODO(), bson.M{"_id": topicID}).Decode(&topic)
		if err != nil {
			c.JSON(404, gin.H{"error": "Topic not found"})
			return
		}

		if topic.CreatedBy != userID.(primitive.ObjectID) {
			c.JSON(403, gin.H{"error": "Not authorized to delete this topic"})
			return
		}
	}

	// 删除 topic 中的所有 posts
	_, err = postsCollection.UpdateMany(context.TODO(),
		bson.M{"topic_id": topicID},
		bson.M{"$set": bson.M{"topic_id": nil}},
	)
	if err != nil {
		log.Printf("Error updating posts topic: %v", err)
		c.JSON(500, gin.H{"error": "Failed to update posts topic"})
		return
	}
	// 删除话题本身
	_, err = collection.DeleteOne(context.TODO(), bson.M{"_id": topicID})
	if err != nil {
		log.Printf("Error deleting topic: %v", err)
		c.JSON(500, gin.H{"error": "Failed to delete topic"})
		return
	}

	c.JSON(200, gin.H{"message": "Topic deleted successfully"})
}

// 修改 deleteComment 函数，不使用事务
func deleteComment(c *gin.Context) {
	commentID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		log.Printf("Invalid comment ID: %v", err)
		c.JSON(400, gin.H{"error": "Invalid comment ID"})
		return
	}

	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "User ID not found"})
		return
	}

	username, _ := c.Get("username")
	collection := client.Database("forum").Collection("comments")

	// 如果不是管理员，检查是否是评论作者
	if username.(string) != "admin" {
		var comment Comment
		err = collection.FindOne(context.TODO(), bson.M{"_id": commentID}).Decode(&comment)
		if err != nil {
			c.JSON(404, gin.H{"error": "Comment not found"})
			return
		}

		if comment.AuthorID != userID.(primitive.ObjectID) {
			c.JSON(403, gin.H{"error": "Not authorized to delete this comment"})
			return
		}
	}

	// 删除评论及其所有回复
	_, err = collection.DeleteMany(context.TODO(), bson.M{
		"$or": []bson.M{
			{"_id": commentID},
			{"parent_id": commentID},
		},
	})

	if err != nil {
		log.Printf("Error deleting comment: %v", err)
		c.JSON(500, gin.H{"error": "Failed to delete comment"})
		return
	}

	c.JSON(200, gin.H{"message": "Comment and replies deleted successfully"})
}

// 修改获取评论的函数以支持嵌套结构
// 修改 getComments 函数以支持嵌套结构和排序
func getComments(c *gin.Context) {
	postID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid post ID"})
		return
	}

	collection := client.Database("forum").Collection("comments")

	// 获取所有评论
	cursor, err := collection.Find(context.TODO(), bson.M{"post_id": postID})
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch comments"})
		return
	}
	defer cursor.Close(context.TODO())

	var allComments []Comment
	if err = cursor.All(context.TODO(), &allComments); err != nil {
		c.JSON(500, gin.H{"error": "Failed to decode comments"})
		return
	}

	// 构建评论树
	commentMap := make(map[string]*Comment)
	var rootComments []*Comment

	// 分离主评论和回复
	for i := range allComments {
		comment := &allComments[i]
		commentMap[comment.ID.Hex()] = comment

		// 如果是主评论（没有 parent_id）
		if comment.ParentID.IsZero() {
			comment.Replies = []Comment{} // 初始化回复数组
			rootComments = append(rootComments, comment)
		}
	}

	// 将回复添加到对应的主评论下
	for _, comment := range allComments {
		if !comment.ParentID.IsZero() {
			if parent, exists := commentMap[comment.ParentID.Hex()]; exists {
				parent.Replies = append(parent.Replies, comment)
			}
		}
	}

	// 转换为可以序列化的格式
	result := make([]Comment, len(rootComments))
	for i, comment := range rootComments {
		// 按时间排序回复
		sort.Slice(comment.Replies, func(i, j int) bool {
			return comment.Replies[i].CreatedAt.Before(comment.Replies[j].CreatedAt)
		})
		result[i] = *comment
	}

	// 按时间倒序排序主评论
	sort.Slice(result, func(i, j int) bool {
		return result[i].CreatedAt.After(result[j].CreatedAt)
	})

	c.JSON(200, result)
}

// 在 main.go 中修改 getLatestComments 函数
func getLatestComments(c *gin.Context) {
	collection := client.Database("forum").Collection("comments")

	// 获取最新的2条评论
	opts := options.Find().
		SetSort(bson.M{"created_at": -1}).
		SetLimit(2)

	cursor, err := collection.Find(context.TODO(), bson.M{}, opts)
	if err != nil {
		log.Printf("Error fetching latest comments: %v", err)
		c.JSON(500, gin.H{"error": "Failed to fetch comments"})
		return
	}
	defer cursor.Close(context.TODO())

	var comments []Comment
	if err = cursor.All(context.TODO(), &comments); err != nil {
		log.Printf("Error decoding comments: %v", err)
		c.JSON(500, gin.H{"error": "Failed to decode comments"})
		return
	}

	c.JSON(200, comments)
}

// 获取所有分类
func getCategories(c *gin.Context) {
	// 这里可以从数据库中获取分类，或者直接返回预定义的分类列表
	categories := []string{
		"讨论",
		"问答",
		"分享",
		"建议",
		"其他",
	}
	c.JSON(200, categories)
}

func main() {
	// 连接MongoDB
	mongoURI := os.Getenv("MONGODB_URI")
	if mongoURI == "" {
		mongoURI = "mongodb://localhost:27017"
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	clientOptions := options.Client().ApplyURI(mongoURI)
	var err error                                   // 这里声明一个新的 err 变量
	client, err = mongo.Connect(ctx, clientOptions) // 使用 = 而不是 :=
	if err != nil {
		log.Fatal(err)
	}

	// 检查连接
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}
	log.SetFlags(log.LstdFlags | log.Lshortfile) // 添加文件名和行号到日志

	// 初始化云存储必须在设置路由之前
	if err := initCloudStorage(); err != nil {
		log.Fatalf("Failed to initialize cloud storage: %v", err)
	}
	// 执行迁移
	migrateExistingFilesToCloud()

	// 初始化Gin路由
	r := gin.Default()

	// 信任特定代理
	err = r.SetTrustedProxies([]string{"127.0.0.1"})
	if err != nil {
		log.Printf("Failed to set trusted proxies: %v", err)
		// 或者 log.Fatal(err)，取决于是否要终止程序
	}
	//git add . && git commit -m "add" && git push origin master
	// 将现有的 CORS 配置替换为：
	// 在 main.go 中修改 CORS 配置
	// main.go 中的 CORS 配置
	r.Use(cors.New(cors.Config{
		AllowOrigins: []string{
			"http://localhost:5173",               // 本地开发环境
			"http://127.0.0.1:5173",               // 本地开发环境
			"https://www.suxingchahui.space",      // 生产环境域名
			"https://my-login-app-one.vercel.app", // Vercel 部署的前端域名
		},
		AllowMethods: []string{
			"GET",
			"POST",
			"PUT",
			"PATCH",
			"DELETE",
			"HEAD",
			"OPTIONS",
		},
		AllowHeaders: []string{
			"Origin",
			"Content-Length",
			"Content-Type",
			"Authorization",
			"Cache-Control",
		},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))
	// Create uploads directory if it doesn't exist
	uploadsDir := "./uploads"
	if err := os.MkdirAll(uploadsDir, 0755); err != nil {
		log.Printf("Error creating uploads directory: %v", err)
	}

	// 静态文件服务
	r.Static("/uploads", "./uploads")

	// API路由
	api := r.Group("/api")
	{
		// 添加一个测试路由
		api.GET("/test-oss", func(c *gin.Context) {
			if cloudStorage == nil || cloudStorage.bucket == nil {
				c.JSON(500, gin.H{"error": "Storage not initialized"})
				return
			}
			c.JSON(200, gin.H{"status": "OSS connection OK"})
		})
		// 文件上传
		api.POST("/upload", authMiddleware(), HandleFileUpload)
		// 用户相关
		api.GET("/users/:id/posts", authMiddleware(), getUserPosts)
		api.GET("/users/:id/comments", authMiddleware(), getUserComments)
		api.GET("/verify", authMiddleware(), verifyToken)
		// 认证相关
		api.POST("/register", handleRegister)
		api.POST("/login", handleLogin)
		api.GET("/verify-email", handleVerifyEmail) // 注意这里不需要 authMiddleware

		// 帖子相关
		api.GET("/posts", getPosts)
		api.GET("/posts/:id", getPost)
		api.GET("/categories", getCategories)
		api.POST("/posts", authMiddleware(), createPost)
		api.PUT("/posts/:id", authMiddleware(), updatePost)
		api.DELETE("/posts/:id", authMiddleware(), deletePost)
		api.DELETE("/comments/:id", authMiddleware(), deleteComment)
		api.DELETE("/topics/:id", authMiddleware(), deleteTopic)

		// 评论相关
		api.GET("/posts/:id/comments", getComments)
		api.GET("/latest-comments", getLatestComments)
		api.POST("/posts/:id/comments", authMiddleware(), createComment)

		api.POST("/comments/:id/reply", authMiddleware(), handleReply)
		api.POST("/comments/:id/like", authMiddleware(), handleLike)
		api.DELETE("/comments/:id/like", authMiddleware(), handleUnlike)

		api.GET("/community-stats", getCommunityStats)

		// 发现页面相关
		api.GET("/discover", getPopularPosts)
		api.GET("/discover/topics/:topic", getPostsByTopic)

		// 话题相关
		api.GET("/topics", getTopics)
		api.POST("/topics", authMiddleware(), createTopic)
		api.GET("/topics/:id", getTopic)
		api.GET("/topics/:id/posts", getTopicPosts)

		// 排行榜相关
		api.GET("/ranking/users", getUserRanking)
		api.GET("/ranking/posts", getPostRanking)

		// 通知相关
		api.GET("/notifications", authMiddleware(), getNotifications)
		api.PUT("/notifications/read", authMiddleware(), markNotificationsAsRead)

		// 用户设置相关
		api.PUT("/users/profile", authMiddleware(), updateUserProfile)
		api.PUT("/users/password", authMiddleware(), updatePassword)

		// 搜索相关
		api.GET("/search", handleSearch)

		// 消息相关
		api.GET("/messages", authMiddleware(), getMessages)
		api.POST("/messages", authMiddleware(), sendMessage)
		api.PUT("/messages/:id/read", authMiddleware(), markMessageRead)
		api.GET("/messages/unread-count", authMiddleware(), getUnreadCount)

		// 添加一个检查路由来查看迁移结果
		api.GET("/check-migration", func(c *gin.Context) {
			collection := client.Database("forum").Collection("posts")

			cursor, err := collection.Find(context.TODO(), bson.M{
				"imageURL": bson.M{
					"$exists": true,
					"$ne":     "",
				},
			})
			if err != nil {
				c.JSON(500, gin.H{"error": "Failed to fetch posts"})
				return
			}
			defer cursor.Close(context.TODO())

			var posts []struct {
				ID       primitive.ObjectID `json:"_id"`
				ImageURL string             `json:"imageURL"`
			}
			if err = cursor.All(context.TODO(), &posts); err != nil {
				c.JSON(500, gin.H{"error": "Failed to decode posts"})
				return
			}

			c.JSON(200, posts)
		})
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Fatal(r.Run(":" + port))
	// 每24小时清理一次未验证的账户
	go func() {
		for {
			cleanupUnverifiedAccounts()
			time.Sleep(24 * time.Hour)
		}
	}()
}

// 搜索处理函数
func handleSearch(c *gin.Context) {
	query := c.Query("q")
	searchType := c.Query("type") // 可选参数：all, posts, topics, users
	if query == "" {
		c.JSON(400, gin.H{"error": "Search query is required"})
		return
	}

	// 创建上下文和通道
	ctx := context.TODO()
	resultChan := make(chan SearchResult)
	errorChan := make(chan error)

	// 创建模糊搜索的正则表达式
	searchRegex := primitive.Regex{Pattern: query, Options: "i"}

	go func() {
		var result SearchResult
		var wg sync.WaitGroup

		// 搜索帖子
		if searchType == "all" || searchType == "posts" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				posts := []SearchPost{}

				// 聚合管道，包含评论数统计
				pipeline := mongo.Pipeline{
					{{Key: "$match", Value: bson.M{
						"$or": []bson.M{
							{"title": bson.M{"$regex": searchRegex}},
							{"content": bson.M{"$regex": searchRegex}},
							{"tags": bson.M{"$in": []string{query}}},
						},
					}}},
					{{Key: "$lookup", Value: bson.M{
						"from":         "comments",
						"localField":   "_id",
						"foreignField": "post_id",
						"as":           "comments",
					}}},
					{{Key: "$addFields", Value: bson.M{
						"comment_count": bson.M{"$size": "$comments"},
					}}},
					{{Key: "$sort", Value: bson.M{
						"created_at": -1,
					}}},
					{{Key: "$limit", Value: 10}},
				}

				cursor, err := client.Database("forum").Collection("posts").Aggregate(ctx, pipeline)
				if err == nil {
					cursor.All(ctx, &posts)
				}
				result.Posts = posts
			}()
		}

		// 搜索话题
		if searchType == "all" || searchType == "topics" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				topics := []Topic{}

				pipeline := mongo.Pipeline{
					{{Key: "$match", Value: bson.M{
						"$or": []bson.M{
							{"title": bson.M{"$regex": searchRegex}},
							{"description": bson.M{"$regex": searchRegex}},
						},
					}}},
					{{Key: "$lookup", Value: bson.M{
						"from":         "posts",
						"localField":   "_id",
						"foreignField": "topic_id",
						"as":           "posts",
					}}},
					{{Key: "$addFields", Value: bson.M{
						"post_count": bson.M{"$size": "$posts"},
					}}},
					{{Key: "$sort", Value: bson.M{
						"post_count": -1,
					}}},
					{{Key: "$limit", Value: 5}},
				}

				cursor, err := client.Database("forum").Collection("topics").Aggregate(ctx, pipeline)
				if err == nil {
					cursor.All(ctx, &topics)
				}
				result.Topics = topics
			}()
		}

		// 搜索用户
		if searchType == "all" || searchType == "users" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				users := []UserInfo{}

				pipeline := mongo.Pipeline{
					{{Key: "$match", Value: bson.M{
						"$or": []bson.M{
							{"username": bson.M{"$regex": searchRegex}},
							{"bio": bson.M{"$regex": searchRegex}},
						},
					}}},
					{{Key: "$project", Value: bson.M{
						"username": 1,
						"avatar":   1,
						"bio":      1,
					}}},
					{{Key: "$limit", Value: 5}},
				}

				cursor, err := client.Database("forum").Collection("users").Aggregate(ctx, pipeline)
				if err == nil {
					cursor.All(ctx, &users)
				}
				result.Users = users
			}()
		}

		wg.Wait()
		resultChan <- result
	}()

	// 等待结果或超时
	select {
	case result := <-resultChan:
		c.JSON(200, result)
	case err := <-errorChan:
		c.JSON(500, gin.H{"error": err.Error()})
	case <-time.After(5 * time.Second):
		c.JSON(504, gin.H{"error": "Search timeout"})
	}
}

// 标记消息为已读
func markMessageRead(c *gin.Context) {
	userID, _ := c.Get("user_id")
	messageID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid message ID"})
		return
	}

	collection := client.Database("forum").Collection("messages")

	// 确保只能标记发给自己的消息为已读
	result, err := collection.UpdateOne(
		context.TODO(),
		bson.M{
			"_id":     messageID,
			"to_id":   userID.(primitive.ObjectID),
			"is_read": false,
		},
		bson.M{"$set": bson.M{"is_read": true}},
	)

	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to mark message as read"})
		return
	}

	if result.ModifiedCount == 0 {
		c.JSON(404, gin.H{"error": "Message not found or already read"})
		return
	}

	c.JSON(200, gin.H{"message": "Message marked as read"})
}

// 获取未读消息数量
func getUnreadCount(c *gin.Context) {
	userID, _ := c.Get("user_id")
	collection := client.Database("forum").Collection("messages")

	// 统计发送给当前用户的未读消息数量
	count, err := collection.CountDocuments(
		context.TODO(),
		bson.M{
			"to_id":   userID.(primitive.ObjectID),
			"is_read": false,
		},
	)

	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to get unread count"})
		return
	}

	c.JSON(200, gin.H{"count": count})
}

// 获取消息列表
func getMessages(c *gin.Context) {
	userID, _ := c.Get("user_id")
	collection := client.Database("forum").Collection("messages")

	cursor, err := collection.Find(context.TODO(), bson.M{
		"$or": []bson.M{
			{"from_id": userID.(primitive.ObjectID)},
			{"to_id": userID.(primitive.ObjectID)},
		},
	}, options.Find().SetSort(bson.M{"created_at": -1}))

	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch messages"})
		return
	}

	var messages []Message
	if err = cursor.All(context.TODO(), &messages); err != nil {
		c.JSON(500, gin.H{"error": "Failed to decode messages"})
		return
	}

	c.JSON(200, messages)
}

// 发送消息
func sendMessage(c *gin.Context) {
	fromID, _ := c.Get("user_id")
	var message struct {
		ToID    string `json:"to_id"`
		Content string `json:"content"`
	}

	if err := c.ShouldBindJSON(&message); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	toID, err := primitive.ObjectIDFromHex(message.ToID)
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid recipient ID"})
		return
	}

	newMessage := Message{
		ID:        primitive.NewObjectID(),
		FromID:    fromID.(primitive.ObjectID),
		ToID:      toID,
		Content:   message.Content,
		IsRead:    false,
		CreatedAt: time.Now(),
	}

	collection := client.Database("forum").Collection("messages")
	_, err = collection.InsertOne(context.TODO(), newMessage)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to send message"})
		return
	}

	c.JSON(201, newMessage)
}

func getPostsByTopic(c *gin.Context) {
	topicID, err := primitive.ObjectIDFromHex(c.Param("topic"))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid topic ID"})
		return
	}

	collection := client.Database("forum").Collection("posts")
	cursor, err := collection.Find(context.TODO(), bson.M{"topic_id": topicID})
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch posts"})
		return
	}
	defer cursor.Close(context.TODO())

	var posts []Post
	if err = cursor.All(context.TODO(), &posts); err != nil {
		c.JSON(500, gin.H{"error": "Failed to decode posts"})
		return
	}

	c.JSON(200, posts)
}

func createTopic(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var topic Topic
	if err := c.ShouldBindJSON(&topic); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	topic.ID = primitive.NewObjectID()
	topic.CreatedBy = userID.(primitive.ObjectID)
	topic.CreatedAt = time.Now()
	topic.Posts = []primitive.ObjectID{}

	collection := client.Database("forum").Collection("topics")
	_, err := collection.InsertOne(context.TODO(), topic)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create topic"})
		return
	}

	c.JSON(201, topic)
}

func getTopic(c *gin.Context) {
	topicID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid topic ID"})
		return
	}

	collection := client.Database("forum").Collection("topics")
	var topic Topic
	err = collection.FindOne(context.TODO(), bson.M{"_id": topicID}).Decode(&topic)
	if err != nil {
		c.JSON(404, gin.H{"error": "Topic not found"})
		return
	}

	c.JSON(200, topic)
}

func getTopicPosts(c *gin.Context) {
	topicID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid topic ID"})
		return
	}

	collection := client.Database("forum").Collection("posts")
	cursor, err := collection.Find(context.TODO(), bson.M{"topic_id": topicID})
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch posts"})
		return
	}
	defer cursor.Close(context.TODO())

	var posts []Post
	if err = cursor.All(context.TODO(), &posts); err != nil {
		c.JSON(500, gin.H{"error": "Failed to decode posts"})
		return
	}

	c.JSON(200, posts)
}

func getUserRanking(c *gin.Context) {
	collection := client.Database("forum").Collection("posts")

	pipeline := mongo.Pipeline{
		{{Key: "$group", Value: bson.M{
			"_id":        "$author_id",
			"username":   bson.M{"$first": "$author"},
			"post_count": bson.M{"$sum": 1},
		}}},
		{{Key: "$sort", Value: bson.M{"post_count": -1}}},
		{{Key: "$limit", Value: 10}},
	}

	cursor, err := collection.Aggregate(context.TODO(), pipeline)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch user ranking"})
		return
	}

	var rankings []struct {
		ID        primitive.ObjectID `bson:"_id" json:"_id"`
		Username  string             `bson:"username" json:"username"`
		PostCount int                `bson:"post_count" json:"post_count"`
	}

	if err = cursor.All(context.TODO(), &rankings); err != nil {
		c.JSON(500, gin.H{"error": "Failed to decode rankings"})
		return
	}

	c.JSON(200, rankings)
}

func getPostRanking(c *gin.Context) {
	collection := client.Database("forum").Collection("posts")

	pipeline := mongo.Pipeline{
		{{Key: "$lookup", Value: bson.M{
			"from":         "comments",
			"localField":   "_id",
			"foreignField": "post_id",
			"as":           "comments",
		}}},
		{{Key: "$addFields", Value: bson.M{
			"comment_count": bson.M{"$size": "$comments"},
		}}},
		{{Key: "$sort", Value: bson.M{
			"comment_count": -1,
			"created_at":    -1,
		}}},
		{{Key: "$limit", Value: 10}},
	}

	cursor, err := collection.Aggregate(context.TODO(), pipeline)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch post ranking"})
		return
	}

	var posts []Post
	if err = cursor.All(context.TODO(), &posts); err != nil {
		c.JSON(500, gin.H{"error": "Failed to decode posts"})
		return
	}

	c.JSON(200, posts)
}

func updatePassword(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var passwords struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}

	if err := c.ShouldBindJSON(&passwords); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// 获取用户当前密码
	collection := client.Database("forum").Collection("users")
	var user User
	err := collection.FindOne(context.TODO(), bson.M{"_id": userID.(primitive.ObjectID)}).Decode(&user)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch user"})
		return
	}

	// 验证旧密码
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(passwords.OldPassword))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid old password"})
		return
	}

	// 加密新密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(passwords.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to hash new password"})
		return
	}

	// 更新密码
	_, err = collection.UpdateOne(
		context.TODO(),
		bson.M{"_id": userID.(primitive.ObjectID)},
		bson.M{"$set": bson.M{"password": string(hashedPassword)}},
	)

	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to update password"})
		return
	}

	c.JSON(200, gin.H{"message": "Password updated successfully"})
}

// 处理函数实现
func getPopularPosts(c *gin.Context) {
	collection := client.Database("forum").Collection("posts")

	// 获取最近7天的帖子，按评论数和点赞数排序
	sevenDaysAgo := time.Now().AddDate(0, 0, -7)

	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{
			"created_at": bson.M{"$gte": sevenDaysAgo},
		}}},
		{{Key: "$lookup", Value: bson.M{
			"from":         "comments",
			"localField":   "_id",
			"foreignField": "post_id",
			"as":           "comments",
		}}},
		{{Key: "$addFields", Value: bson.M{
			"comment_count": bson.M{"$size": "$comments"},
		}}},
		{{Key: "$sort", Value: bson.M{
			"comment_count": -1,
			"created_at":    -1,
		}}},
		{{Key: "$limit", Value: 20}},
	}

	cursor, err := collection.Aggregate(context.TODO(), pipeline)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch posts"})
		return
	}

	var posts []Post
	if err = cursor.All(context.TODO(), &posts); err != nil {
		c.JSON(500, gin.H{"error": "Failed to decode posts"})
		return
	}

	c.JSON(200, posts)
}

func getTopics(c *gin.Context) {
	collection := client.Database("forum").Collection("topics")

	cursor, err := collection.Find(context.TODO(), bson.M{})
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch topics"})
		return
	}

	var topics []Topic
	if err = cursor.All(context.TODO(), &topics); err != nil {
		c.JSON(500, gin.H{"error": "Failed to decode topics"})
		return
	}

	c.JSON(200, topics)
}

// 创建通知，并添加日志记录
func createNotification(userID primitive.ObjectID, postID primitive.ObjectID, notificationType string, content string) error {
	log.Printf("Creating notification for user %s, post %s, type %s", userID.Hex(), postID.Hex(), notificationType)

	notification := Notification{
		ID:        primitive.NewObjectID(),
		UserID:    userID,
		Type:      notificationType,
		Content:   content,
		PostID:    postID,
		IsRead:    false,
		CreatedAt: time.Now(),
	}

	collection := client.Database("forum").Collection("notifications")
	result, err := collection.InsertOne(context.TODO(), notification)
	if err != nil {
		log.Printf("Error creating notification: %v", err)
		return err
	}
	log.Printf("Successfully created notification with ID: %v", result.InsertedID)
	return nil
}

// 获取通知列表时添加日志
func getNotifications(c *gin.Context) {
	userID, _ := c.Get("user_id")
	log.Printf("Fetching notifications for user: %s", userID.(primitive.ObjectID).Hex())

	collection := client.Database("forum").Collection("notifications")

	options := options.Find().
		SetSort(bson.M{"created_at": -1}).
		SetLimit(50)

	cursor, err := collection.Find(context.TODO(),
		bson.M{"user_id": userID.(primitive.ObjectID)},
		options,
	)
	if err != nil {
		log.Printf("Error fetching notifications: %v", err)
		c.JSON(500, gin.H{"error": "Failed to fetch notifications"})
		return
	}
	defer cursor.Close(context.TODO())

	var notifications []Notification
	if err = cursor.All(context.TODO(), &notifications); err != nil {
		log.Printf("Error decoding notifications: %v", err)
		c.JSON(500, gin.H{"error": "Failed to decode notifications"})
		return
	}

	log.Printf("Found %d notifications for user %s", len(notifications), userID.(primitive.ObjectID).Hex())
	c.JSON(200, notifications)
}

// 标记通知为已读
func markNotificationsAsRead(c *gin.Context) {
	userID, _ := c.Get("user_id")
	collection := client.Database("forum").Collection("notifications")

	_, err := collection.UpdateMany(
		context.TODO(),
		bson.M{
			"user_id": userID.(primitive.ObjectID),
			"is_read": false,
		},
		bson.M{"$set": bson.M{"is_read": true}},
	)

	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to mark notifications as read"})
		return
	}

	c.JSON(200, gin.H{"message": "All notifications marked as read"})
}

func updateUserProfile(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var updateData struct {
		Nickname string `json:"nickname"`
		Email    string `json:"email"`
		Bio      string `json:"bio"`
	}

	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	collection := client.Database("forum").Collection("users")
	_, err := collection.UpdateOne(
		context.TODO(),
		bson.M{"_id": userID.(primitive.ObjectID)},
		bson.M{"$set": bson.M{
			"username": updateData.Nickname,
			"email":    updateData.Email,
			"bio":      updateData.Bio,
		}},
	)

	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to update profile"})
		return
	}

	c.JSON(200, gin.H{"message": "Profile updated successfully"})
}

// 删除未验证的过期账户
func cleanupUnverifiedAccounts() {
	collection := client.Database("forum").Collection("users")

	// 删除24小时前未验证的账户
	filter := bson.M{
		"is_verified": false,
		"created_at": bson.M{
			"$lt": time.Now().Add(-24 * time.Hour),
		},
	}

	result, err := collection.DeleteMany(context.TODO(), filter)
	if err != nil {
		log.Printf("Error cleaning up unverified accounts: %v", err)
		return
	}

	log.Printf("Cleaned up %v unverified accounts", result.DeletedCount)
}

// 验证令牌
func verifyToken(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		c.JSON(401, gin.H{"error": "Unauthorized"})
		return
	}

	username, _ := c.Get("username")
	c.JSON(200, gin.H{
		"user_id":  userID,
		"username": username,
	})
}

func sendVerificationEmail(to, token string) error {
	m := gomail.NewMessage()

	// 修改 From 头部格式，确保符合 RFC 5322 规范
	m.SetHeader("From", fmt.Sprintf("%s <%s>", "Tea Forum", emailConfig.From))
	m.SetHeader("To", to)
	m.SetHeader("Subject", "验证您的邮箱")
	//git add . && git commit -m "add" && git push origin master
	//verifyLink := fmt.Sprintf("http://localhost:5173/verify-email?token=%s", token)
	verifyLink := fmt.Sprintf("https://www.suxingchahui.space/verify-email?token=%s", token)
	htmlBody := fmt.Sprintf(`
        <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #333;">欢迎注册茶会!</h2>
            <p style="color: #666;">请点击下面的链接验证你的邮箱:</p>
            <a href="%s" style="display: inline-block; padding: 10px 20px; background-color: #4F46E5; color: white; text-decoration: none; border-radius: 5px;">验证邮箱</a>
            <p style="color: #666; margin-top: 20px;">此链接24小时内有效</p>
        </div>
    `, verifyLink)

	m.SetBody("text/html", htmlBody)

	// 使用 465 端口并启用 SSL
	d := gomail.NewDialer(emailConfig.SmtpHost, 465, emailConfig.From, emailConfig.AuthCode)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	if err := d.DialAndSend(m); err != nil {
		log.Printf("Error sending email: %v", err)
		return fmt.Errorf("failed to send email: %v", err)
	}

	return nil
}

func handleVerifyEmail(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		log.Printf("Missing verification token")
		c.JSON(400, gin.H{"error": "无效的验证链接"})
		return
	}

	log.Printf("Verifying email with token: %s", token)

	collection := client.Database("forum").Collection("users")

	// 首先尝试查找用户
	var user User
	err := collection.FindOne(context.TODO(), bson.M{
		"verify_token": token,
	}).Decode(&user)

	// 如果找不到用户，再查找已验证的用户
	if err != nil {
		var verifiedUser User
		err = collection.FindOne(context.TODO(), bson.M{
			"is_verified": true,
		}).Decode(&verifiedUser)
		if err == nil {
			c.JSON(200, gin.H{"message": "邮箱已经验证过了，请直接登录"})
			return
		}
		log.Printf("Error finding user: %v", err)
		c.JSON(400, gin.H{"error": "无效的验证链接"})
		return
	}

	// 检查是否已验证
	if user.IsVerified {
		c.JSON(200, gin.H{"message": "邮箱已经验证过了，请直接登录"})
		return
	}

	// 更新用户状态
	result, err := collection.UpdateOne(
		context.TODO(),
		bson.M{"_id": user.ID},
		bson.M{
			"$set": bson.M{
				"is_verified":      true,
				"verify_token":     "",
				"token_expired_at": time.Time{},
			},
		},
	)

	if err != nil {
		log.Printf("Error updating user: %v", err)
		c.JSON(500, gin.H{"error": "验证邮箱失败，请重试"})
		return
	}

	log.Printf("Successfully verified user %s. ModifiedCount: %d", user.Username, result.ModifiedCount)
	c.JSON(200, gin.H{"message": "邮箱验证成功！"})
}

func isValidEmail(email string) bool {
	// 基本的邮箱格式验证
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	match, err := regexp.MatchString(pattern, email)
	if err != nil {
		return false
	}
	return match
}
func generateRandomToken() string {
	// 生成32字节的随机数据
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return ""
	}
	// 转换为16进制字符串
	return hex.EncodeToString(bytes)
}

// Modify handleRegister function
func handleRegister(c *gin.Context) {
	// 打印原始请求体
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		log.Printf("Error reading request body: %v", err)
		c.JSON(400, gin.H{"error": "无法读取请求数据"})
		return
	}
	// 打印原始请求体
	log.Printf("Raw request body: %s", string(body))
	// 重新设置请求体
	c.Request.Body = io.NopCloser(bytes.NewBuffer(body))

	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		log.Printf("Error binding JSON: %v", err)
		c.JSON(400, gin.H{"error": "请提供用户名、密码和邮箱"})
		return
	}

	// 打印接收到的数据
	log.Printf("Received registration data - Username: %s, Email: %s, Password length: %d",
		user.Username, user.Email, len(user.Password))

	// 验证必要字段
	if user.Username == "" || user.Password == "" || user.Email == "" {
		log.Printf("Missing required fields - Username: %v, Password: %v, Email: %v",
			user.Username != "", user.Password != "", user.Email != "")
		c.JSON(400, gin.H{"error": "用户名、密码和邮箱都不能为空"})
		return
	}

	// 验证邮箱格式
	if !isValidEmail(user.Email) {
		log.Printf("Invalid email format: %s", user.Email)
		c.JSON(400, gin.H{"error": "Invalid email format"})
		return
	}

	collection := client.Database("forum").Collection("users")
	var existingUser User
	err = collection.FindOne(context.TODO(), bson.M{
		"$or": []bson.M{
			{"username": user.Username},
			{"email": user.Email},
		},
	}).Decode(&existingUser)
	if err == nil {
		log.Printf("User already exists - Username: %s, Email: %s", user.Username, user.Email)
		c.JSON(400, gin.H{"error": "Username or email already exists"})
		return
	}

	verifyToken := generateRandomToken()
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Printf("Error hashing password: %v", err)
		c.JSON(500, gin.H{"error": "Error processing password"})
		return
	}

	newUser := User{
		Username:       user.Username,
		Password:       string(hashedPassword),
		Email:          user.Email,
		IsVerified:     false,
		VerifyToken:    verifyToken,
		TokenExpiredAt: time.Now().Add(24 * time.Hour),
		CreatedAt:      time.Now(),
	}

	_, err = collection.InsertOne(context.TODO(), newUser)
	if err != nil {
		log.Printf("Error creating user: %v", err)
		c.JSON(500, gin.H{"error": "Failed to create user"})
		return
	}

	// 发送验证邮件
	if err := sendVerificationEmail(user.Email, verifyToken); err != nil {
		log.Printf("Failed to send verification email: %v", err)
	}

	log.Printf("Successfully registered user: %s with email: %s", user.Username, user.Email)
	c.JSON(201, gin.H{"message": "User created successfully"})
}

func handleLogin(c *gin.Context) {
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	// 读取请求体
	if err := c.ShouldBindJSON(&credentials); err != nil {
		log.Printf("Invalid request: %v", err)
		c.JSON(400, gin.H{"error": "无效的请求"})
		return
	}

	// 确保密码不为空
	if credentials.Password == "" || credentials.Username == "" {
		c.JSON(400, gin.H{"error": "用户名和密码不能为空"})
		return
	}

	collection := client.Database("forum").Collection("users")
	var user User

	// 查找用户
	err := collection.FindOne(context.TODO(), bson.M{
		"username": credentials.Username,
	}).Decode(&user)

	if err != nil {
		log.Printf("User not found: %v", err)
		c.JSON(401, gin.H{"error": "用户名或密码错误"})
		return
	}

	// 检查密码长度和内容
	log.Printf("Login attempt - Username: %s, Password length: %d",
		credentials.Username, len(credentials.Password))

	// 验证密码 - 直接使用字节比较
	err = bcrypt.CompareHashAndPassword(
		[]byte(user.Password),
		[]byte(credentials.Password),
	)

	if err != nil {
		log.Printf("Password verification failed: %v", err)
		c.JSON(401, gin.H{"error": "用户名或密码错误"})
		return
	}

	// 检查邮箱验证状态
	if !user.IsVerified {
		c.JSON(401, gin.H{"error": "请先验证邮箱后再登录"})
		return
	}

	// 生成 token
	claims := &Claims{
		ID:       user.ID.Hex(),
		Username: user.Username,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(24 * time.Hour)),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtSecret)
	if err != nil {
		log.Printf("Token generation failed: %v", err)
		c.JSON(500, gin.H{"error": "生成令牌失败"})
		return
	}

	c.JSON(200, gin.H{
		"token": tokenString,
		"user": gin.H{
			"id":          user.ID.Hex(),
			"username":    user.Username,
			"email":       user.Email,
			"is_verified": user.IsVerified,
			"created_at":  user.CreatedAt,
		},
	})
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization header"})
			c.Abort()
			return
		}

		tokenString := authHeader[7:]
		claims := &Claims{}

		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtSecret, nil
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			c.Abort()
			return
		}

		userID, err := primitive.ObjectIDFromHex(claims.ID)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Invalid user ID"})
			c.Abort()
			return
		}

		c.Set("user_id", userID)
		c.Set("username", claims.Username)
		log.Printf("Incoming request from origin: %s", c.Request.Header.Get("Origin"))
		log.Printf("Request method: %s", c.Request.Method)
		log.Printf("Request headers: %+v", c.Request.Header)
		c.Next()
	}
}

// 修改获取帖子列表的函数，支持分页和筛选
func getPosts(c *gin.Context) {
	// 获取分页参数
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}

	// 构建查询条件
	filter := bson.M{}

	// 添加分类筛选
	if category := c.Query("category"); category != "" {
		filter["category"] = category
	}

	// 添加话题筛选
	if topicID := c.Query("topic_id"); topicID != "" {
		objectID, err := primitive.ObjectIDFromHex(topicID)
		if err == nil {
			filter["topic_id"] = objectID
		}
	}

	collection := client.Database("forum").Collection("posts")

	// 获取总数
	total, err := collection.CountDocuments(context.TODO(), filter)
	if err != nil {
		log.Printf("Error counting posts: %v", err)
		c.JSON(500, gin.H{"error": "Failed to count posts"})
		return
	}

	// 构建聚合管道
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: filter}},
		{{Key: "$lookup", Value: bson.M{
			"from":         "topics",
			"localField":   "topic_id",
			"foreignField": "_id",
			"as":           "topic",
		}}},
		{{Key: "$unwind", Value: bson.M{
			"path":                       "$topic",
			"preserveNullAndEmptyArrays": true,
		}}},
		{{Key: "$sort", Value: bson.M{"created_at": -1}}},
		{{Key: "$skip", Value: (page - 1) * pageSize}},
		{{Key: "$limit", Value: pageSize}},
	}

	cursor, err := collection.Aggregate(context.TODO(), pipeline)
	if err != nil {
		log.Printf("Error fetching posts: %v", err)
		c.JSON(500, gin.H{"error": "Failed to fetch posts"})
		return
	}
	defer cursor.Close(context.TODO())

	var posts []Post
	if err = cursor.All(context.TODO(), &posts); err != nil {
		log.Printf("Error decoding posts: %v", err)
		c.JSON(500, gin.H{"error": "Failed to decode posts"})
		return
	}

	// 计算总页数
	totalPages := int(math.Ceil(float64(total) / float64(pageSize)))

	c.JSON(200, gin.H{
		"posts":      posts,
		"total":      total,
		"page":       page,
		"pageSize":   pageSize,
		"totalPages": totalPages,
	})
}

func getPost(c *gin.Context) {
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid post ID"})
		return
	}

	collection := client.Database("forum").Collection("posts")
	commentsCollection := client.Database("forum").Collection("comments")

	// 获取帖子信息
	var post Post
	err = collection.FindOne(context.TODO(), bson.M{"_id": id}).Decode(&post)
	if err != nil {
		c.JSON(404, gin.H{"error": "Post not found"})
		return
	}

	// 先获取主评论
	mainCommentsFilter := bson.M{
		"post_id":   id,
		"parent_id": bson.M{"$exists": false}, // 只获取主评论
	}
	mainCommentsCursor, err := commentsCollection.Find(context.TODO(), mainCommentsFilter)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch comments"})
		return
	}
	defer mainCommentsCursor.Close(context.TODO())

	var mainComments []Comment
	if err = mainCommentsCursor.All(context.TODO(), &mainComments); err != nil {
		c.JSON(500, gin.H{"error": "Failed to decode comments"})
		return
	}

	// 获取每个主评论的回复
	for i := range mainComments {
		repliesFilter := bson.M{"parent_id": mainComments[i].ID}
		repliesCursor, err := commentsCollection.Find(context.TODO(), repliesFilter)
		if err != nil {
			continue
		}
		defer repliesCursor.Close(context.TODO())

		var replies []Comment
		if err = repliesCursor.All(context.TODO(), &replies); err != nil {
			continue
		}

		mainComments[i].Replies = replies
	}

	// 返回帖子和评论数据
	c.JSON(200, gin.H{
		"post":     post,
		"comments": mainComments,
	})
}

func createPost(c *gin.Context) {
	userID, _ := c.Get("user_id")
	username, _ := c.Get("username")

	var post Post
	if err := c.ShouldBindJSON(&post); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	post.ID = primitive.NewObjectID()
	post.AuthorID = userID.(primitive.ObjectID)
	post.Author = username.(string)
	post.CreatedAt = time.Now()

	// 如果指定了话题，更新话题的帖子列表
	if !post.TopicID.IsZero() {
		topicsCollection := client.Database("forum").Collection("topics")
		_, err := topicsCollection.UpdateOne(
			context.TODO(),
			bson.M{"_id": post.TopicID},
			bson.M{"$push": bson.M{"posts": post.ID}},
		)
		if err != nil {
			c.JSON(500, gin.H{"error": "Failed to update topic"})
			return
		}
	}

	collection := client.Database("forum").Collection("posts")
	_, err := collection.InsertOne(context.TODO(), post)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create post"})
		return
	}

	c.JSON(201, post)
}

// 修改 createComment 函数，更新通知逻辑
func createComment(c *gin.Context) {
	postID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid post ID"})
		return
	}

	userID, _ := c.Get("user_id")
	username, _ := c.Get("username")

	var comment Comment
	if err := c.ShouldBindJSON(&comment); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// 先获取帖子信息
	postsCollection := client.Database("forum").Collection("posts")
	var post Post
	err = postsCollection.FindOne(context.TODO(), bson.M{"_id": postID}).Decode(&post)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch post"})
		return
	}

	// 创建评论
	comment.ID = primitive.NewObjectID()
	comment.PostID = postID
	comment.AuthorID = userID.(primitive.ObjectID)
	comment.Author = username.(string)
	comment.CreatedAt = time.Now()
	comment.Likes = []primitive.ObjectID{}
	comment.Replies = []Comment{}

	collection := client.Database("forum").Collection("comments")
	_, err = collection.InsertOne(context.TODO(), comment)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create comment"})
		return
	}

	// 如果评论者不是帖子作者，创建通知
	if post.AuthorID != userID.(primitive.ObjectID) {
		log.Printf("Creating comment notification: commenter=%s, post_author=%s", userID.(primitive.ObjectID).Hex(), post.AuthorID.Hex())
		notificationContent := fmt.Sprintf("%s 评论了你的帖子《%s》", username.(string), post.Title)
		err = createNotification(post.AuthorID, postID, "comment", notificationContent)
		if err != nil {
			log.Printf("Error creating notification: %v", err)
		}
	}

	// 更新帖子的评论数
	_, err = postsCollection.UpdateOne(
		context.TODO(),
		bson.M{"_id": postID},
		bson.M{"$inc": bson.M{"comments_count": 1}},
	)
	if err != nil {
		log.Printf("Error updating post comment count: %v", err)
	}

	c.JSON(201, comment)
}

// 修改 handleReply 函数，更新通知逻辑
func handleReply(c *gin.Context) {
	parentID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid comment ID"})
		return
	}

	collection := client.Database("forum").Collection("comments")

	// 获取父评论信息
	var parentComment Comment
	err = collection.FindOne(context.TODO(), bson.M{"_id": parentID}).Decode(&parentComment)
	if err != nil {
		c.JSON(404, gin.H{"error": "Parent comment not found"})
		return
	}

	userID, _ := c.Get("user_id")
	username, _ := c.Get("username")

	var input struct {
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(400, gin.H{"error": "Invalid content"})
		return
	}

	// 创建回复
	reply := Comment{
		ID:        primitive.NewObjectID(),
		PostID:    parentComment.PostID,
		Content:   input.Content,
		AuthorID:  userID.(primitive.ObjectID),
		Author:    username.(string),
		CreatedAt: time.Now(),
		ParentID:  parentID,
		Likes:     []primitive.ObjectID{},
	}

	// 插入回复
	_, err = collection.InsertOne(context.TODO(), reply)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create reply"})
		return
	}

	// 如果回复者不是原评论作者，创建通知
	if parentComment.AuthorID != userID.(primitive.ObjectID) {
		// 获取帖子信息
		postsCollection := client.Database("forum").Collection("posts")
		var post Post
		err = postsCollection.FindOne(context.TODO(), bson.M{"_id": parentComment.PostID}).Decode(&post)
		if err == nil {
			log.Printf("Creating reply notification: replier=%s, comment_author=%s", userID.(primitive.ObjectID).Hex(), parentComment.AuthorID.Hex())
			notificationContent := fmt.Sprintf("%s 回复了你在《%s》中的评论", username.(string), post.Title)
			err = createNotification(parentComment.AuthorID, parentComment.PostID, "reply", notificationContent)
			if err != nil {
				log.Printf("Error creating notification: %v", err)
			}
		}
	}

	// 更新父评论以包含新回复
	_, err = collection.UpdateOne(
		context.TODO(),
		bson.M{"_id": parentID},
		bson.M{"$push": bson.M{"replies": reply}},
	)
	if err != nil {
		log.Printf("Error updating parent comment with reply: %v", err)
	}

	// 更新帖子的评论计数
	postsCollection := client.Database("forum").Collection("posts")
	_, err = postsCollection.UpdateOne(
		context.TODO(),
		bson.M{"_id": parentComment.PostID},
		bson.M{"$inc": bson.M{"comments_count": 1}},
	)
	if err != nil {
		log.Printf("Error updating post comment count: %v", err)
	}

	c.JSON(201, reply)
}

// 处理点赞
func handleLike(c *gin.Context) {
	commentID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid comment ID"})
		return
	}

	userID, _ := c.Get("user_id")
	collection := client.Database("forum").Collection("comments")

	_, err = collection.UpdateOne(
		context.TODO(),
		bson.M{"_id": commentID},
		bson.M{
			"$addToSet": bson.M{
				"likes": userID.(primitive.ObjectID),
			},
		},
	)

	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to like comment"})
		return
	}

	c.JSON(200, gin.H{"message": "Comment liked successfully"})
}

// 处理取消点赞
func handleUnlike(c *gin.Context) {
	commentID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid comment ID"})
		return
	}

	userID, _ := c.Get("user_id")
	collection := client.Database("forum").Collection("comments")

	_, err = collection.UpdateOne(
		context.TODO(),
		bson.M{"_id": commentID},
		bson.M{
			"$pull": bson.M{
				"likes": userID.(primitive.ObjectID),
			},
		},
	)

	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to unlike comment"})
		return
	}

	c.JSON(200, gin.H{"message": "Comment unliked successfully"})
}
