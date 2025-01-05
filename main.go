// go run .
// git add . && git commit -m "add new" && git push origin master
package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/aliyun/aliyun-oss-go-sdk/oss"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var client *mongo.Client
var cloudStorage *CloudStorage
var emailConfig EmailConfig
var jwtSecret = []byte(os.Getenv("JWT_SECRET")) // 使用全局变量，并初始化

// 初始化函数
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

	// 设置邮件配置
	emailConfig = EmailConfig{
		From:     os.Getenv("EMAIL_FROM"),
		AuthCode: os.Getenv("EMAIL_AUTH_CODE"),
		SmtpHost: os.Getenv("EMAIL_SMTP_HOST"),
		SmtpPort: os.Getenv("EMAIL_SMTP_PORT"),
	}
}

// 初始化云存储
func initCloudStorage() error {
	required := []string{"OSS_ACCESS_KEY_ID", "OSS_ACCESS_KEY_SECRET", "OSS_ENDPOINT", "OSS_BUCKET"}
	for _, env := range required {
		if os.Getenv(env) == "" {
			return fmt.Errorf("missing required environment variable: %s", env)
		}
	}

	log.Printf("Initializing OSS client with endpoint: %s, bucket: %s",
		os.Getenv("OSS_ENDPOINT"),
		os.Getenv("OSS_BUCKET"))

	client, err := oss.New(
		os.Getenv("OSS_ENDPOINT"),
		os.Getenv("OSS_ACCESS_KEY_ID"),
		os.Getenv("OSS_ACCESS_KEY_SECRET"),
	)
	if err != nil {
		return fmt.Errorf("failed to create OSS client: %v", err)
	}

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

// 清理无效评论的辅助函数
func cleanupOrphanedComments() {
	log.Println("Starting orphaned comments cleanup...")

	commentsCollection := client.Database("forum").Collection("comments")

	// 查找所有已删除帖子的评论
	pipeline := mongo.Pipeline{
		bson.D{
			{Key: "$lookup", Value: bson.M{
				"from":         "posts",
				"localField":   "post_id",
				"foreignField": "_id",
				"as":           "post",
			}},
		},
		bson.D{
			{Key: "$match", Value: bson.M{
				"post": bson.M{"$size": 0},
			}},
		},
	}

	cursor, err := commentsCollection.Aggregate(context.TODO(), pipeline)
	if err != nil {
		log.Printf("Error in aggregation: %v", err)
		return
	}
	defer cursor.Close(context.TODO())

	var orphanedComments []Comment
	if err = cursor.All(context.TODO(), &orphanedComments); err != nil {
		log.Printf("Error decoding comments: %v", err)
		return
	}

	if len(orphanedComments) > 0 {
		var commentIds []primitive.ObjectID
		for _, comment := range orphanedComments {
			commentIds = append(commentIds, comment.ID)
		}

		// 批量删除所有孤立的评论
		result, err := commentsCollection.DeleteMany(context.TODO(), bson.M{
			"_id": bson.M{"$in": commentIds},
		})
		if err != nil {
			log.Printf("Error deleting orphaned comments: %v", err)
			return
		}

		log.Printf("Successfully deleted %d orphaned comments", result.DeletedCount)
	} else {
		log.Println("No orphaned comments found")
	}
}

// 迁移现有文件到云存储
func migrateExistingFilesToCloud() {
	log.Println("Starting database image URLs migration...")
	collection := client.Database("forum").Collection("posts")

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
		filename := filepath.Base(post.ImageURL)
		objectKey := "uploads/" + filename
		cloudURL := fmt.Sprintf("https://%s.%s/%s",
			os.Getenv("OSS_BUCKET"),
			os.Getenv("OSS_ENDPOINT"),
			objectKey)

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

func setupRouter() *gin.Engine {
	r := gin.Default()

	// CORS配置
	r.Use(cors.New(cors.Config{
		AllowOrigins: []string{
			"http://localhost:5173",
			"http://127.0.0.1:5173",
			"https://www.suxingchahui.space",
			"https://my-login-app-one.vercel.app",
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

	// 创建上传目录
	if err := os.MkdirAll("./uploads", 0755); err != nil {
		log.Printf("Error creating uploads directory: %v", err)
	}

	// 静态文件服务
	r.Static("/uploads", "./uploads")

	// API路由
	api := r.Group("/api")
	{
		// 测试路由
		api.GET("/test-oss", func(c *gin.Context) {
			if cloudStorage == nil || cloudStorage.bucket == nil {
				c.JSON(500, gin.H{"error": "Storage not initialized"})
				return
			}
			c.JSON(200, gin.H{"status": "OSS connection OK"})
		})

		// 文件上传
		api.POST("/upload", authMiddleware(), handleFileUpload)

		// 用户相关
		api.GET("/users/:id/posts", authMiddleware(), getUserPosts)
		api.GET("/users/:id/comments", authMiddleware(), getUserComments)
		api.GET("/verify", authMiddleware(), verifyToken)

		// 认证相关
		api.POST("/register", handleRegister)
		api.POST("/login", handleLogin)
		api.GET("/verify-email", handleVerifyEmail)

		// 密码重置相关路由
		r.POST("/api/forgot-password", handleForgotPassword)
		r.GET("/api/check-reset-token", handleCheckResetToken)
		r.POST("/api/reset-password", handleResetPassword)

		// 帖子相关
		api.GET("/posts", getPosts)
		api.GET("/posts/:id", getPost)
		api.GET("/categories", getCategories)
		api.POST("/posts", authMiddleware(), createPost)
		api.PUT("/posts/:id", authMiddleware(), updatePost)
		api.DELETE("/posts/:id", authMiddleware(), deletePost)

		// 评论相关
		api.GET("/posts/:id/comments", getComments)
		api.GET("/latest-comments", getLatestComments)
		api.POST("/posts/:id/comments", authMiddleware(), createComment)
		api.POST("/comments/:id/reply", authMiddleware(), handleReply)
		api.POST("/comments/:id/like", authMiddleware(), handleLike)
		api.DELETE("/comments/:id/like", authMiddleware(), handleUnlike)
		api.DELETE("/comments/:id", authMiddleware(), deleteComment)

		// 话题相关
		api.GET("/topics", getTopics)
		api.POST("/topics", authMiddleware(), createTopic)
		api.GET("/topics/:id", getTopic)
		api.GET("/topics/:id/posts", getTopicPosts)
		api.DELETE("/topics/:id", authMiddleware(), deleteTopic)

		// 统计相关
		api.GET("/community-stats", getCommunityStats)
		api.GET("/discover", getPopularPosts)
		api.GET("/discover/topics/:topic", getPostsByTopic)

		// 排行榜相关
		api.GET("/ranking/users", getUserRanking)
		api.GET("/ranking/posts", getPostRanking)

		// 通知相关
		api.GET("/notifications", authMiddleware(), getNotifications)
		api.PUT("/notifications/read", authMiddleware(), markNotificationsAsRead)

		// 用户设置相关
		api.GET("/users/:id", getUserProfile)
		api.PUT("/users/profile", authMiddleware(), updateUserProfile)
		api.PUT("/users/password", authMiddleware(), updatePassword)

		// 搜索相关
		api.GET("/search", handleSearch)

		// 消息相关
		api.GET("/messages", authMiddleware(), getMessages)
		api.POST("/messages", authMiddleware(), sendMessage)
		api.PUT("/messages/:id/read", authMiddleware(), markMessageRead)
		api.GET("/messages/unread-count", authMiddleware(), getUnreadCount)
	}

	return r
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
	var err error
	client, err = mongo.Connect(ctx, clientOptions)
	if err != nil {
		log.Fatal(err)
	}

	// 检查连接
	err = client.Ping(ctx, nil)
	if err != nil {
		log.Fatal(err)
	}

	// 设置日志格式
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	// 初始化云存储
	if err := initCloudStorage(); err != nil {
		log.Fatalf("Failed to initialize cloud storage: %v", err)
	}

	// 执行图片文件迁移
	migrateExistingFilesToCloud()

	// 设置路由
	r := setupRouter()

	// 设置信任代理
	if err := r.SetTrustedProxies([]string{"127.0.0.1"}); err != nil {
		log.Printf("Failed to set trusted proxies: %v", err)
	}
	cleanupOrphanedComments()
	// 启动定时清理未验证账户的goroutine
	go func() {
		for {
			cleanupUnverifiedAccounts()
			cleanupOrphanedComments()
			time.Sleep(24 * time.Hour)
		}
	}()

	// 获取端口
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	// 启动服务器
	log.Fatal(r.Run(":" + port))
}
