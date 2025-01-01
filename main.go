package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

var client *mongo.Client
var jwtSecret = []byte(os.Getenv("JWT_SECRET")) // 使用全局变量，并初始化

type User struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	Username  string             `bson:"username"`
	Password  string             `bson:"password"`
	CreatedAt time.Time          `bson:"created_at"`
}

type Claims struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	jwt.RegisteredClaims
}

// Post 结构体添加 CommentsCount 字段
type Post struct {
	ID            primitive.ObjectID `bson:"_id,omitempty" json:"_id"`
	Title         string             `bson:"title" json:"title"`
	Content       string             `bson:"content" json:"content"`
	Category      string             `bson:"category" json:"category"`
	AuthorID      primitive.ObjectID `bson:"author_id" json:"author_id"`
	Author        string             `bson:"author" json:"author"`
	CreatedAt     time.Time          `bson:"created_at" json:"created_at"`
	CommentsCount int                `bson:"comments_count" json:"comments_count"`
	ImageURL      string             `bson:"image_url" json:"imageURL"` // 修改这里
}

type Comment struct {
	ID        primitive.ObjectID `bson:"_id,omitempty"`
	PostID    primitive.ObjectID `bson:"post_id"`
	Content   string             `bson:"content"`
	AuthorID  primitive.ObjectID `bson:"author_id"`
	Author    string             `bson:"author"`
	CreatedAt time.Time          `bson:"created_at"`
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
}

// 文件上传处理
func HandleFileUpload(c *gin.Context) {
	file, err := c.FormFile("file")
	if err != nil {
		c.JSON(400, gin.H{"error": "No file uploaded"})
		return
	}

	// 生成唯一文件名
	filename := time.Now().Format("20060102150405") + "_" + file.Filename
	filepath := "uploads/" + filename

	if err := c.SaveUploadedFile(file, filepath); err != nil {
		c.JSON(500, gin.H{"error": "Failed to save file"})
		return
	}

	c.JSON(200, gin.H{"url": "/uploads/" + filename})
}

// 获取用户帖子
func getUserPosts(c *gin.Context) {
	userID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid user ID"})
		return
	}

	collection := client.Database("forum").Collection("posts")
	cursor, err := collection.Find(context.TODO(), bson.M{"author_id": userID})
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

// 获取用户评论
func getUserComments(c *gin.Context) {
	userID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid user ID"})
		return
	}

	collection := client.Database("forum").Collection("comments")
	cursor, err := collection.Find(context.TODO(), bson.M{"author_id": userID})
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch comments"})
		return
	}
	defer cursor.Close(context.TODO())

	var comments []Comment
	if err = cursor.All(context.TODO(), &comments); err != nil {
		c.JSON(500, gin.H{"error": "Failed to decode comments"})
		return
	}

	c.JSON(200, comments)
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

	var updateData struct {
		Title   string `json:"title"`
		Content string `json:"content"`
	}
	if err := c.ShouldBindJSON(&updateData); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	update := bson.M{
		"$set": bson.M{
			"title":   updateData.Title,
			"content": updateData.Content,
		},
	}

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

	// 如果是管理员，不需要检查作者，直接删除
	if username.(string) == "admin" {
		log.Printf("Admin user detected, proceeding with deletion")
		_, err := collection.DeleteOne(context.TODO(), bson.M{"_id": postID})
		if err != nil {
			log.Printf("Error during admin deletion: %v", err)
			c.JSON(500, gin.H{"error": "Failed to delete post"})
			return
		}

		// 删除相关评论
		commentsCollection := client.Database("forum").Collection("comments")
		_, err = commentsCollection.DeleteMany(context.TODO(), bson.M{"post_id": postID})
		if err != nil {
			log.Printf("Error deleting comments: %v", err)
		}

		log.Printf("Post successfully deleted by admin")
		c.JSON(200, gin.H{"message": "Post deleted successfully by admin"})
		return
	}

	// 非管理员，需要验证作者身份
	var post Post
	err = collection.FindOne(context.TODO(), bson.M{"_id": postID}).Decode(&post)
	if err != nil {
		log.Printf("Error finding post: %v", err)
		c.JSON(404, gin.H{"error": "Post not found"})
		return
	}

	log.Printf("Post author ID: %v, Current user ID: %v", post.AuthorID, userID)
	if post.AuthorID != userID.(primitive.ObjectID) {
		log.Printf("User not authorized to delete this post")
		c.JSON(403, gin.H{"error": "Not authorized to delete this post"})
		return
	}

	_, err = collection.DeleteOne(context.TODO(), bson.M{"_id": postID})
	if err != nil {
		log.Printf("Error during deletion: %v", err)
		c.JSON(500, gin.H{"error": "Failed to delete post"})
		return
	}

	// 删除相关评论
	commentsCollection := client.Database("forum").Collection("comments")
	_, err = commentsCollection.DeleteMany(context.TODO(), bson.M{"post_id": postID})
	if err != nil {
		log.Printf("Error deleting comments: %v", err)
	}

	log.Printf("Post successfully deleted by author")
	c.JSON(200, gin.H{"message": "Post deleted successfully"})
}
func deleteComment(c *gin.Context) {
	commentID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		log.Printf("Invalid comment ID: %v", err)
		c.JSON(400, gin.H{"error": "Invalid comment ID"})
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

	log.Printf("Delete comment request - Comment ID: %v, User ID: %v, Username: %v", commentID, userID, username)

	collection := client.Database("forum").Collection("comments")

	// 如果是管理员，直接删除
	if username.(string) == "admin" {
		log.Printf("Admin user detected, proceeding with comment deletion")
		_, err := collection.DeleteOne(context.TODO(), bson.M{"_id": commentID})
		if err != nil {
			log.Printf("Error during admin comment deletion: %v", err)
			c.JSON(500, gin.H{"error": "Failed to delete comment"})
			return
		}

		log.Printf("Comment successfully deleted by admin")
		c.JSON(200, gin.H{"message": "Comment deleted successfully by admin"})
		return
	}

	// 非管理员，需要验证评论作者身份
	var comment Comment
	err = collection.FindOne(context.TODO(), bson.M{"_id": commentID}).Decode(&comment)
	if err != nil {
		log.Printf("Error finding comment: %v", err)
		c.JSON(404, gin.H{"error": "Comment not found"})
		return
	}

	log.Printf("Comment author ID: %v, Current user ID: %v", comment.AuthorID, userID)
	if comment.AuthorID != userID.(primitive.ObjectID) {
		log.Printf("User not authorized to delete this comment")
		c.JSON(403, gin.H{"error": "Not authorized to delete this comment"})
		return
	}

	_, err = collection.DeleteOne(context.TODO(), bson.M{"_id": commentID})
	if err != nil {
		log.Printf("Error during deletion: %v", err)
		c.JSON(500, gin.H{"error": "Failed to delete comment"})
		return
	}

	log.Printf("Comment successfully deleted by author")
	c.JSON(200, gin.H{"message": "Comment deleted successfully"})
}

func getComments(c *gin.Context) {
	postID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid post ID"})
		return
	}

	collection := client.Database("forum").Collection("comments")
	cursor, err := collection.Find(context.TODO(), bson.M{"post_id": postID})
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch comments"})
		return
	}
	defer cursor.Close(context.TODO())

	var comments []Comment
	if err = cursor.All(context.TODO(), &comments); err != nil {
		c.JSON(500, gin.H{"error": "Failed to decode comments"})
		return
	}

	c.JSON(200, comments)
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

	// 初始化Gin路由
	r := gin.Default()

	// 信任特定代理
	err = r.SetTrustedProxies([]string{"127.0.0.1"})
	if err != nil {
		log.Printf("Failed to set trusted proxies: %v", err)
		// 或者 log.Fatal(err)，取决于是否要终止程序
	}

	// 将现有的 CORS 配置替换为：
	r.Use(cors.New(cors.Config{
		//AllowOrigins:   []string{"http://localhost:5173", "http://127.0.0.1:5173"}, // 本地开发环境
		AllowOrigins:     []string{"https://my-login-app-one.vercel.app"}, // 替换为你的 Vercel 域名
		AllowMethods:     []string{"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Length", "Content-Type", "Authorization"},
		ExposeHeaders:    []string{"Content-Length"},
		AllowCredentials: true,
		MaxAge:           12 * time.Hour,
	}))
	// 创建上传目录
	if err := os.MkdirAll("uploads", 0755); err != nil {
		log.Fatal(err)
	}

	// 静态文件服务
	r.Static("/uploads", "./uploads")

	// API路由
	api := r.Group("/api")
	{
		// 文件上传
		api.POST("/upload", authMiddleware(), HandleFileUpload)
		// 用户相关
		api.GET("/users/:id/posts", authMiddleware(), getUserPosts)
		api.GET("/users/:id/comments", authMiddleware(), getUserComments)
		api.GET("/verify", authMiddleware(), verifyToken)
		// 认证相关
		api.POST("/register", handleRegister)
		api.POST("/login", handleLogin)

		// 帖子相关
		api.GET("/posts", getPosts)
		api.GET("/posts/:id", getPost)
		api.POST("/posts", authMiddleware(), createPost)
		api.PUT("/posts/:id", authMiddleware(), updatePost)
		api.DELETE("/posts/:id", authMiddleware(), deletePost)
		api.DELETE("/comments/:id", authMiddleware(), deleteComment)

		// 评论相关
		api.GET("/posts/:id/comments", getComments)
		api.GET("/latest-comments", getLatestComments)
		api.POST("/posts/:id/comments", authMiddleware(), createComment)
	}

	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Fatal(r.Run(":" + port))
}

func handleRegister(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// 检查用户名是否已存在
	collection := client.Database("forum").Collection("users")
	var existingUser User
	err := collection.FindOne(context.TODO(), bson.M{"username": user.Username}).Decode(&existingUser)
	if err == nil {
		c.JSON(400, gin.H{"error": "Username already exists"})
		return
	}

	// 加密密码
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(500, gin.H{"error": "Internal server error"})
		return
	}

	// 创建新用户
	user.Password = string(hashedPassword)
	user.CreatedAt = time.Now()

	result, err := collection.InsertOne(context.TODO(), user)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create user"})
		return
	}

	c.JSON(201, gin.H{"id": result.InsertedID})
}

func handleLogin(c *gin.Context) {
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&credentials); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	// 查找用户
	collection := client.Database("forum").Collection("users")
	var user User
	err := collection.FindOne(context.TODO(), bson.M{"username": credentials.Username}).Decode(&user)
	if err != nil {
		c.JSON(401, gin.H{"error": "Invalid credentials"})
		return
	}

	// 验证密码
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password))
	if err != nil {
		c.JSON(401, gin.H{"error": "Invalid credentials"})
		return
	}

	// 生成JWT
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
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Could not generate token"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"token": tokenString,
		"user": gin.H{
			"id":       user.ID.Hex(),
			"username": user.Username,
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
		c.Next()
	}
}

func getPosts(c *gin.Context) {
	collection := client.Database("forum").Collection("posts")

	cursor, err := collection.Find(context.TODO(), bson.M{}, options.Find().SetSort(bson.M{"created_at": -1}))
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

	c.JSON(200, posts)
}

func getPost(c *gin.Context) {
	id, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		log.Printf("Invalid post ID: %v", err)
		c.JSON(400, gin.H{"error": "Invalid post ID"})
		return
	}

	log.Printf("Fetching post with ID: %s", id.Hex())

	collection := client.Database("forum").Collection("posts")
	var post Post
	err = collection.FindOne(context.TODO(), bson.M{"_id": id}).Decode(&post)
	if err != nil {
		log.Printf("Error finding post: %v", err)
		c.JSON(404, gin.H{"error": "Post not found"})
		return
	}

	// 获取评论
	commentsCollection := client.Database("forum").Collection("comments")
	cursor, err := commentsCollection.Find(context.TODO(), bson.M{"post_id": id})
	if err != nil {
		log.Printf("Error fetching comments: %v", err)
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

	log.Printf("Successfully fetched post and %d comments", len(comments))

	c.JSON(200, gin.H{
		"post":     post,
		"comments": comments,
	})
}

func createPost(c *gin.Context) {
	userID, exists := c.Get("user_id")
	if !exists {
		log.Printf("User ID not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Unauthorized"})
		return
	}

	username, exists := c.Get("username")
	if !exists {
		log.Printf("Username not found in context")
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Username not found"})
		return
	}

	// 创建一个新的 Post 结构体来接收数据
	var post Post
	if err := c.ShouldBindJSON(&post); err != nil {
		log.Printf("Error binding JSON: %v", err)
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 验证必需字段
	if post.Title == "" || post.Content == "" || post.Category == "" {
		log.Printf("Missing required fields")
		c.JSON(http.StatusBadRequest, gin.H{"error": "Title, content and category are required"})
		return
	}

	// 设置帖子的其他字段
	post.ID = primitive.NewObjectID() // 生成新的 ID
	post.AuthorID = userID.(primitive.ObjectID)
	post.Author = username.(string)
	post.CreatedAt = time.Now().UTC()
	post.CommentsCount = 0

	// 打印帖子数据以便调试
	log.Printf("Creating post: %+v", post)

	collection := client.Database("forum").Collection("posts")
	result, err := collection.InsertOne(context.TODO(), post)
	if err != nil {
		log.Printf("Error inserting post: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create post"})
		return
	}

	// 获取已创建的帖子
	var createdPost Post
	err = collection.FindOne(context.TODO(), bson.M{"_id": result.InsertedID}).Decode(&createdPost)
	if err != nil {
		log.Printf("Error fetching created post: %v", err)
		c.JSON(http.StatusOK, gin.H{
			"id":      result.InsertedID,
			"message": "Post created successfully",
		})
		return
	}

	// 返回已创建的帖子
	log.Printf("Successfully created post: %+v", createdPost)
	c.JSON(http.StatusCreated, createdPost)
}

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
	comment.ID = primitive.NewObjectID()
	comment.PostID = postID
	comment.AuthorID = userID.(primitive.ObjectID)
	comment.Author = username.(string)
	comment.CreatedAt = time.Now()

	collection := client.Database("forum").Collection("comments")
	result, err := collection.InsertOne(context.TODO(), comment)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create comment"})
		return
	}

	c.JSON(201, gin.H{"id": result.InsertedID})
}
