package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/gomail.v2"
)

// 生成随机token
func generateRandomToken() string {
	bytes := make([]byte, 32)
	if _, err := rand.Read(bytes); err != nil {
		return ""
	}
	return hex.EncodeToString(bytes)
}

// 验证邮箱格式
func isValidEmail(email string) bool {
	pattern := `^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`
	match, err := regexp.MatchString(pattern, email)
	if err != nil {
		return false
	}
	return match
}

// 发送验证邮件
func sendVerificationEmail(to, token string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", fmt.Sprintf("%s <%s>", "Tea Forum", emailConfig.From))
	m.SetHeader("To", to)
	m.SetHeader("Subject", "验证您的邮箱")

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

	d := gomail.NewDialer(emailConfig.SmtpHost, 465, emailConfig.From, emailConfig.AuthCode)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	if err := d.DialAndSend(m); err != nil {
		log.Printf("Error sending email: %v", err)
		return fmt.Errorf("failed to send email: %v", err)
	}

	return nil
}

// 注册处理
func handleRegister(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		log.Printf("Error binding JSON: %v", err)
		c.JSON(400, gin.H{"error": "请提供用户名、密码和邮箱"})
		return
	}

	// 验证必要字段
	if user.Username == "" || user.Password == "" || user.Email == "" {
		log.Printf("Missing required fields")
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
	err := collection.FindOne(context.TODO(), bson.M{
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

	if err := sendVerificationEmail(user.Email, verifyToken); err != nil {
		log.Printf("Failed to send verification email: %v", err)
	}

	log.Printf("Successfully registered user: %s with email: %s", user.Username, user.Email)
	c.JSON(201, gin.H{"message": "User created successfully"})
}

// 登录处理
func handleLogin(c *gin.Context) {
	var credentials struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&credentials); err != nil {
		log.Printf("Invalid request: %v", err)
		c.JSON(400, gin.H{"error": "无效的请求"})
		return
	}

	if credentials.Password == "" || credentials.Username == "" {
		c.JSON(400, gin.H{"error": "用户名和密码不能为空"})
		return
	}

	collection := client.Database("forum").Collection("users")
	var user User
	err := collection.FindOne(context.TODO(), bson.M{
		"username": credentials.Username,
	}).Decode(&user)

	if err != nil {
		log.Printf("User not found: %v", err)
		c.JSON(401, gin.H{"error": "用户名或密码错误"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(credentials.Password))
	if err != nil {
		log.Printf("Password verification failed: %v", err)
		c.JSON(401, gin.H{"error": "用户名或密码错误"})
		return
	}

	if !user.IsVerified {
		c.JSON(401, gin.H{"error": "请先验证邮箱后再登录"})
		return
	}

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

// 验证邮箱处理
func handleVerifyEmail(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		log.Printf("Missing verification token")
		c.JSON(400, gin.H{"error": "无效的验证链接"})
		return
	}

	log.Printf("Verifying email with token: %s", token)
	collection := client.Database("forum").Collection("users")

	var user User
	err := collection.FindOne(context.TODO(), bson.M{
		"verify_token": token,
	}).Decode(&user)

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

	if user.IsVerified {
		c.JSON(200, gin.H{"message": "邮箱已经验证过了，请直接登录"})
		return
	}

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

// 认证中间件
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

// 更新密码
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

	collection := client.Database("forum").Collection("users")
	var user User
	err := collection.FindOne(context.TODO(), bson.M{"_id": userID.(primitive.ObjectID)}).Decode(&user)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch user"})
		return
	}

	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(passwords.OldPassword))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid old password"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(passwords.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to hash new password"})
		return
	}

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

// 删除未验证的过期账户
func cleanupUnverifiedAccounts() {
	collection := client.Database("forum").Collection("users")

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

// auth_helper.go 中添加以下函数

// 发送重置密码邮件
func sendResetPasswordEmail(to, token string) error {
	m := gomail.NewMessage()
	m.SetHeader("From", fmt.Sprintf("%s <%s>", "Tea Forum", emailConfig.From))
	m.SetHeader("To", to)
	m.SetHeader("Subject", "重置密码")

	resetLink := fmt.Sprintf("https://www.suxingchahui.space/reset-password?token=%s", token)
	htmlBody := fmt.Sprintf(`
        <div style="max-width: 600px; margin: 0 auto; padding: 20px;">
            <h2 style="color: #333;">重置密码</h2>
            <p style="color: #666;">请点击下面的链接重置您的密码:</p>
            <a href="%s" style="display: inline-block; padding: 10px 20px; background-color: #4F46E5; color: white; text-decoration: none; border-radius: 5px;">重置密码</a>
            <p style="color: #666; margin-top: 20px;">此链接1小时内有效</p>
            <p style="color: #666;">如果您没有请求重置密码，请忽略此邮件</p>
        </div>
    `, resetLink)

	m.SetBody("text/html", htmlBody)
	d := gomail.NewDialer(emailConfig.SmtpHost, 465, emailConfig.From, emailConfig.AuthCode)
	d.TLSConfig = &tls.Config{InsecureSkipVerify: true}

	if err := d.DialAndSend(m); err != nil {
		log.Printf("Error sending reset password email: %v", err)
		return fmt.Errorf("failed to send email: %v", err)
	}

	return nil
}

// 发起重置密码
func handleForgotPassword(c *gin.Context) {
	var input struct {
		Email string `json:"email"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(400, gin.H{"error": "请提供邮箱地址"})
		return
	}

	collection := client.Database("forum").Collection("users")
	var user User
	err := collection.FindOne(context.TODO(), bson.M{"email": input.Email}).Decode(&user)
	if err != nil {
		c.JSON(400, gin.H{"error": "该邮箱未注册"})
		return
	}

	resetToken := generateRandomToken()
	expireTime := time.Now().Add(1 * time.Hour)

	_, err = collection.UpdateOne(
		context.TODO(),
		bson.M{"_id": user.ID},
		bson.M{
			"$set": bson.M{
				"reset_token":            resetToken,
				"reset_token_expired_at": expireTime,
			},
		},
	)
	if err != nil {
		c.JSON(500, gin.H{"error": "系统错误，请稍后重试"})
		return
	}

	if err := sendResetPasswordEmail(user.Email, resetToken); err != nil {
		c.JSON(500, gin.H{"error": "发送邮件失败，请稍后重试"})
		return
	}

	c.JSON(200, gin.H{"message": "重置密码链接已发送到您的邮箱"})
}

// 验证重置密码token
func handleCheckResetToken(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		c.JSON(400, gin.H{"error": "无效的重置链接"})
		return
	}

	collection := client.Database("forum").Collection("users")
	var user User
	err := collection.FindOne(context.TODO(), bson.M{
		"reset_token":            token,
		"reset_token_expired_at": bson.M{"$gt": time.Now()},
	}).Decode(&user)

	if err != nil {
		c.JSON(400, gin.H{"error": "重置链接已过期或无效"})
		return
	}

	c.JSON(200, gin.H{"valid": true})
}

// 重置密码
func handleResetPassword(c *gin.Context) {
	var input struct {
		Token       string `json:"token"`
		NewPassword string `json:"new_password"`
	}
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(400, gin.H{"error": "请提供新密码"})
		return
	}

	collection := client.Database("forum").Collection("users")
	var user User
	err := collection.FindOne(context.TODO(), bson.M{
		"reset_token":            input.Token,
		"reset_token_expired_at": bson.M{"$gt": time.Now()},
	}).Decode(&user)

	if err != nil {
		c.JSON(400, gin.H{"error": "重置链接已过期或无效"})
		return
	}

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(input.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(500, gin.H{"error": "处理新密码时出错"})
		return
	}

	_, err = collection.UpdateOne(
		context.TODO(),
		bson.M{"_id": user.ID},
		bson.M{
			"$set": bson.M{
				"password":               string(hashedPassword),
				"reset_token":            "",
				"reset_token_expired_at": time.Time{},
			},
		},
	)

	if err != nil {
		c.JSON(500, gin.H{"error": "更新密码失败"})
		return
	}

	c.JSON(200, gin.H{"message": "密码已成功重置"})
}
