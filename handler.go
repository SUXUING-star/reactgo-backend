package main

import (
	"context"
	"fmt"
	"log"
	"math"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

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

// 帖子相关处理函数
func getPosts(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))
	if page < 1 {
		page = 1
	}
	if pageSize < 1 {
		pageSize = 10
	}

	filter := bson.M{}
	if category := c.Query("category"); category != "" {
		filter["category"] = category
	}
	if topicID := c.Query("topic_id"); topicID != "" {
		objectID, err := primitive.ObjectIDFromHex(topicID)
		if err == nil {
			filter["topic_id"] = objectID
		}
	}

	collection := client.Database("forum").Collection("posts")
	total, err := collection.CountDocuments(context.TODO(), filter)
	if err != nil {
		log.Printf("Error counting posts: %v", err)
		c.JSON(500, gin.H{"error": "Failed to count posts"})
		return
	}

	// 修改 pipeline，添加作者头像信息
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: filter}},
		// 关联用户集合获取头像
		{{Key: "$lookup", Value: bson.M{
			"from":         "users",
			"localField":   "author_id",
			"foreignField": "_id",
			"as":           "author_info",
		}}},
		// 关联话题集合
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
		// 添加作者头像字段
		{{Key: "$addFields", Value: bson.M{
			"author_avatar": bson.M{
				"$ifNull": []interface{}{
					bson.M{"$arrayElemAt": []interface{}{"$author_info.avatar", 0}},
					"",
				},
			},
		}}},
		// 清理临时字段
		{{Key: "$project", Value: bson.M{
			"author_info": 0,
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

	var post Post
	err = collection.FindOne(context.TODO(), bson.M{"_id": id}).Decode(&post)
	if err != nil {
		c.JSON(404, gin.H{"error": "Post not found"})
		return
	}

	mainCommentsFilter := bson.M{
		"post_id":   id,
		"parent_id": bson.M{"$exists": false},
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

	c.JSON(200, gin.H{
		"post":     post,
		"comments": mainComments,
	})
}

// 创建帖子
func createPost(c *gin.Context) {
	userID, _ := c.Get("user_id")
	username, _ := c.Get("username")

	// 获取用户信息以获取头像
	var user User
	usersCollection := client.Database("forum").Collection("users")
	err := usersCollection.FindOne(context.TODO(), bson.M{"_id": userID.(primitive.ObjectID)}).Decode(&user)
	if err != nil {
		log.Printf("Error fetching user info: %v", err)
		c.JSON(500, gin.H{"error": "Failed to fetch user info"})
		return
	}

	var post Post
	if err := c.ShouldBindJSON(&post); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	post.ID = primitive.NewObjectID()
	post.AuthorID = userID.(primitive.ObjectID)
	post.Author = username.(string)
	post.AuthorAvatar = user.Avatar // 设置作者头像
	post.CreatedAt = time.Now()

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
	_, err = collection.InsertOne(context.TODO(), post)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create post"})
		return
	}

	c.JSON(201, post)
}

func updatePost(c *gin.Context) {
	postID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid post ID"})
		return
	}

	userID, _ := c.Get("user_id")
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
		Title    string  `json:"title"`
		Content  string  `json:"content"`
		ImageURL string  `json:"imageURL"`
		TopicID  *string `json:"topic_id"`
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

	if updateData.TopicID != nil {
		topicID, err := primitive.ObjectIDFromHex(*updateData.TopicID)
		if err == nil {
			update["$set"].(bson.M)["topic_id"] = topicID
		} else {
			update["$set"].(bson.M)["topic_id"] = nil
		}
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
	commentsCollection := client.Database("forum").Collection("comments")

	// 开启事务
	session, err := client.StartSession()
	if err != nil {
		log.Printf("Error starting session: %v", err)
		c.JSON(500, gin.H{"error": "Internal server error"})
		return
	}
	defer session.EndSession(context.TODO())

	// 在事务中执行删除操作
	callback := func(sessCtx mongo.SessionContext) (interface{}, error) {
		// 检查权限
		if username.(string) != "admin" {
			var post Post
			err = collection.FindOne(sessCtx, bson.M{"_id": postID}).Decode(&post)
			if err != nil {
				return nil, err
			}

			if post.AuthorID != userID.(primitive.ObjectID) {
				return nil, fmt.Errorf("not authorized to delete this post")
			}
		}

		// 删除帖子
		_, err = collection.DeleteOne(sessCtx, bson.M{"_id": postID})
		if err != nil {
			return nil, err
		}

		// 删除相关评论
		deleteResult, err := commentsCollection.DeleteMany(sessCtx, bson.M{"post_id": postID})
		if err != nil {
			return nil, err
		}

		return deleteResult.DeletedCount, nil
	}

	// 执行事务
	result, err := session.WithTransaction(context.TODO(), callback)
	if err != nil {
		if err.Error() == "not authorized to delete this post" {
			c.JSON(403, gin.H{"error": "Not authorized to delete this post"})
		} else {
			log.Printf("Error in transaction: %v", err)
			c.JSON(500, gin.H{"error": "Failed to delete post and comments"})
		}
		return
	}

	deletedCommentsCount := result.(int64)
	c.JSON(200, gin.H{
		"message":                "Post and all related comments deleted successfully",
		"deleted_comments_count": deletedCommentsCount,
	})
}

// 话题相关处理函数
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

	_, err = postsCollection.UpdateMany(context.TODO(),
		bson.M{"topic_id": topicID},
		bson.M{"$set": bson.M{"topic_id": nil}},
	)
	if err != nil {
		log.Printf("Error updating posts topic: %v", err)
		c.JSON(500, gin.H{"error": "Failed to update posts topic"})
		return
	}

	_, err = collection.DeleteOne(context.TODO(), bson.M{"_id": topicID})
	if err != nil {
		log.Printf("Error deleting topic: %v", err)
		c.JSON(500, gin.H{"error": "Failed to delete topic"})
		return
	}

	c.JSON(200, gin.H{"message": "Topic deleted successfully"})
}

// 评论相关处理函数
func getComments(c *gin.Context) {
	postID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid post ID"})
		return
	}

	collection := client.Database("forum").Collection("comments")

	// 只获取主评论
	pipeline := mongo.Pipeline{
		{{Key: "$match", Value: bson.M{
			"post_id":   postID,
			"parent_id": bson.M{"$exists": false}, // 只获取主评论
		}}},
		{{Key: "$sort", Value: bson.M{"created_at": -1}}}, // 按时间倒序排序
		{{Key: "$limit", Value: 5}},                       // 限制返回数量
	}

	cursor, err := collection.Aggregate(context.TODO(), pipeline)
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

	// 直接返回评论数组
	c.JSON(200, comments)
}

// 创建评论
func createComment(c *gin.Context) {
	postID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid post ID"})
		return
	}

	userID, _ := c.Get("user_id")
	username, _ := c.Get("username")

	// 获取用户信息以获取头像
	var user User
	usersCollection := client.Database("forum").Collection("users")
	err = usersCollection.FindOne(context.TODO(), bson.M{"_id": userID.(primitive.ObjectID)}).Decode(&user)
	if err != nil {
		log.Printf("Error fetching user info: %v", err)
		c.JSON(500, gin.H{"error": "Failed to fetch user info"})
		return
	}

	var comment Comment
	if err := c.ShouldBindJSON(&comment); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request"})
		return
	}

	comment.ID = primitive.NewObjectID()
	comment.PostID = postID
	comment.AuthorID = userID.(primitive.ObjectID)
	comment.Author = username.(string)
	comment.AuthorAvatar = user.Avatar // 设置作者头像
	comment.CreatedAt = time.Now()
	comment.Likes = []primitive.ObjectID{}
	comment.Replies = []Comment{}
	log.Printf("Comment: %+v", comment)

	collection := client.Database("forum").Collection("comments")
	_, err = collection.InsertOne(context.TODO(), comment)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create comment"})
		return
	}

	// 获取帖子信息并创建通知
	postsCollection := client.Database("forum").Collection("posts")
	var post Post
	err = postsCollection.FindOne(context.TODO(), bson.M{"_id": postID}).Decode(&post)
	if err != nil {
		log.Printf("Error fetching post: %v", err)
	} else {
		// 只有在评论者不是帖子作者时才创建通知
		if post.AuthorID != userID.(primitive.ObjectID) {
			notificationContent := fmt.Sprintf("%s 评论了你的帖子《%s》", username.(string), post.Title)
			err = createNotification(post.AuthorID, postID, "comment", notificationContent)
			if err != nil {
				log.Printf("Error creating notification: %v", err)
			}
		}
	}

	// 更新帖子评论数
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

func handleReply(c *gin.Context) {
	parentID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid comment ID"})
		return
	}

	collection := client.Database("forum").Collection("comments")
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

	_, err = collection.InsertOne(context.TODO(), reply)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to create reply"})
		return
	}

	if parentComment.AuthorID != userID.(primitive.ObjectID) {
		postsCollection := client.Database("forum").Collection("posts")
		var post Post
		err = postsCollection.FindOne(context.TODO(), bson.M{"_id": parentComment.PostID}).Decode(&post)
		if err == nil {
			notificationContent := fmt.Sprintf("%s 回复了你在《%s》中的评论", username.(string), post.Title)
			err = createNotification(parentComment.AuthorID, parentComment.PostID, "reply", notificationContent, parentID)
			if err != nil {
				log.Printf("Error creating notification: %v", err)
			}
		}
	}

	_, err = collection.UpdateOne(
		context.TODO(),
		bson.M{"_id": parentID},
		bson.M{"$push": bson.M{"replies": reply}},
	)
	if err != nil {
		log.Printf("Error updating parent comment with reply: %v", err)
	}

	c.JSON(201, reply)
}

// 用户相关处理函数
func getUserPosts(c *gin.Context) {
	userID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		log.Printf("Invalid user ID: %v", err)
		c.JSON(400, gin.H{"error": "Invalid user ID"})
		return
	}

	collection := client.Database("forum").Collection("posts")
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

	c.JSON(200, posts)
}

func getUserComments(c *gin.Context) {
	userID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		log.Printf("Invalid user ID: %v", err)
		c.JSON(400, gin.H{"error": "Invalid user ID"})
		return
	}

	collection := client.Database("forum").Collection("comments")
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

	c.JSON(200, comments)
}

// 在 handler.go 中更新或添加以下处理函数

// 获取用户信息
func getUserProfile(c *gin.Context) {
	userID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid user ID"})
		return
	}

	collection := client.Database("forum").Collection("users")

	var user UserProfile
	err = collection.FindOne(context.TODO(), bson.M{"_id": userID}).Decode(&user)
	if err != nil {
		if err == mongo.ErrNoDocuments {
			c.JSON(404, gin.H{"error": "User not found"})
		} else {
			log.Printf("Error fetching user: %v", err)
			c.JSON(500, gin.H{"error": "Failed to fetch user"})
		}
		return
	}

	// 构建用户资料响应
	response := gin.H{
		"id":        user.ID,
		"username":  user.Username,
		"bio":       user.Bio,
		"avatar":    user.Avatar,
		"createdAt": user.CreatedAt,
	}

	// 只有用户查看自己的资料时才返回邮箱
	if authUserID, exists := c.Get("user_id"); exists && authUserID.(primitive.ObjectID) == userID {
		response["email"] = user.Email
	}

	c.JSON(200, response)
}

// 更新用户资料
func updateUserProfile(c *gin.Context) {
	userID, _ := c.Get("user_id")

	var input UserUpdateInput
	if err := c.ShouldBindJSON(&input); err != nil {
		c.JSON(400, gin.H{"error": "Invalid request data"})
		return
	}

	// 验证昵称不为空
	if input.Nickname == "" {
		c.JSON(400, gin.H{"error": "Nickname cannot be empty"})
		return
	}

	// 构建更新文档
	update := bson.M{
		"$set": bson.M{
			"username": input.Nickname,
			"bio":      input.Bio,
			"avatar":   input.Avatar,
		},
	}

	// 如果提供了邮箱，也更新邮箱
	if input.Email != "" {
		update["$set"].(bson.M)["email"] = input.Email
	}

	collection := client.Database("forum").Collection("users")
	result, err := collection.UpdateOne(
		context.TODO(),
		bson.M{"_id": userID.(primitive.ObjectID)},
		update,
	)

	if err != nil {
		log.Printf("Error updating user profile: %v", err)
		c.JSON(500, gin.H{"error": "Failed to update profile"})
		return
	}

	if result.ModifiedCount == 0 {
		c.JSON(404, gin.H{"error": "User not found"})
		return
	}

	// 异步更新用户的帖子和评论中的作者名称
	// 在 updateUserProfile 函数的异步更新部分添加头像更新
	go func() {
		postsCollection := client.Database("forum").Collection("posts")
		commentsCollection := client.Database("forum").Collection("comments")

		// 更新帖子中的作者头像
		_, err := postsCollection.UpdateMany(
			context.TODO(),
			bson.M{"author_id": userID.(primitive.ObjectID)},
			bson.M{"$set": bson.M{
				"author":        input.Nickname,
				"author_avatar": input.Avatar,
			}},
		)
		if err != nil {
			log.Printf("Error updating posts author info: %v", err)
		}

		// 更新评论中的作者头像
		_, err = commentsCollection.UpdateMany(
			context.TODO(),
			bson.M{"author_id": userID.(primitive.ObjectID)},
			bson.M{"$set": bson.M{
				"author":        input.Nickname,
				"author_avatar": input.Avatar,
			}},
		)
		if err != nil {
			log.Printf("Error updating comments author info: %v", err)
		}
	}()

	c.JSON(200, gin.H{
		"message": "Profile updated successfully",
		"user": gin.H{
			"username": input.Nickname,
			"email":    input.Email,
			"bio":      input.Bio,
			"avatar":   input.Avatar,
		},
	})
}

// 搜索相关处理函数
func handleSearch(c *gin.Context) {
	query := c.Query("q")
	searchType := c.Query("type")
	if query == "" {
		c.JSON(400, gin.H{"error": "Search query is required"})
		return
	}

	ctx := context.TODO()
	resultChan := make(chan SearchResult)
	errorChan := make(chan error)

	searchRegex := primitive.Regex{Pattern: query, Options: "i"}

	go func() {
		var result SearchResult
		var wg sync.WaitGroup

		if searchType == "all" || searchType == "posts" {
			wg.Add(1)
			go func() {
				defer wg.Done()
				posts := []SearchPost{}

				// 在 handler.go 中修改 handleSearch 函数中的 posts 查询 pipeline
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
						"comments_count": bson.M{"$size": "$comments"},
					}}},
					{{Key: "$project", Value: bson.M{
						"title":          1,
						"content":        1,
						"author":         1,
						"created_at":     1,
						"image_url":      1,
						"comments_count": 1,
						"comments":       1,
					}}},
					{{Key: "$sort", Value: bson.M{"created_at": -1}}},
					{{Key: "$limit", Value: 10}},
				}

				cursor, err := client.Database("forum").Collection("posts").Aggregate(ctx, pipeline)
				if err == nil {
					cursor.All(ctx, &posts)
				}
				for _, post := range posts {
					log.Printf("Post: %+v\n", post)
				}
				result.Posts = posts
			}()
		}

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

	select {
	case result := <-resultChan:
		c.JSON(200, result)
	case err := <-errorChan:
		c.JSON(500, gin.H{"error": err.Error()})
	case <-time.After(5 * time.Second):
		c.JSON(504, gin.H{"error": "Search timeout"})
	}
}

// 通知相关处理函数
func getNotifications(c *gin.Context) {
	userID, _ := c.Get("user_id")
	collection := client.Database("forum").Collection("notifications")

	filter := bson.M{"user_id": userID.(primitive.ObjectID)}
	options := options.Find().
		SetSort(bson.M{"created_at": -1}).
		SetLimit(50)

	cursor, err := collection.Find(context.TODO(), filter, options)
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

	c.JSON(200, notifications)
}

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

// 消息相关处理函数
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

// 创建通知
func createNotification(userID primitive.ObjectID, postID primitive.ObjectID, notificationType string, content string, commentID ...primitive.ObjectID) error {
	notification := Notification{
		ID:        primitive.NewObjectID(),
		UserID:    userID,
		Type:      notificationType,
		Content:   content,
		PostID:    postID,
		IsRead:    false,
		CreatedAt: time.Now(),
	}

	if len(commentID) > 0 {
		notification.CommentID = commentID[0]
	}

	collection := client.Database("forum").Collection("notifications")
	_, err := collection.InsertOne(context.TODO(), notification)
	return err
}

// 修改文件上传处理函数
func handleFileUpload(c *gin.Context) {
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
func markMessageRead(c *gin.Context) {
	userID, _ := c.Get("user_id")
	messageID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid message ID"})
		return
	}

	collection := client.Database("forum").Collection("messages")
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

// 处理点赞

func handleLike(c *gin.Context) {
	commentID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid comment ID"})
		return
	}

	userID, _ := c.Get("user_id")
	username, _ := c.Get("username")
	collection := client.Database("forum").Collection("comments")

	// 获取评论信息
	var comment Comment
	err = collection.FindOne(context.TODO(), bson.M{"_id": commentID}).Decode(&comment)
	if err != nil {
		c.JSON(404, gin.H{"error": "Comment not found"})
		return
	}

	// 检查是否已经点赞
	for _, likeID := range comment.Likes {
		if likeID == userID.(primitive.ObjectID) {
			c.JSON(400, gin.H{"error": "Already liked"})
			return
		}
	}

	// 如果点赞者不是评论作者，创建通知
	if comment.AuthorID != userID.(primitive.ObjectID) {
		postsCollection := client.Database("forum").Collection("posts")
		var post Post
		err = postsCollection.FindOne(context.TODO(), bson.M{"_id": comment.PostID}).Decode(&post)
		if err == nil {
			notificationContent := fmt.Sprintf("%s 赞了你在《%s》中的评论", username.(string), post.Title)
			err = createNotification(comment.AuthorID, post.ID, "like", notificationContent, commentID)
			if err != nil {
				log.Printf("Error creating notification: %v", err)
			}
		}
	}

	// 添加点赞，使用 $addToSet 确保唯一性
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
		log.Printf("Error updating likes: %v", err)
		c.JSON(500, gin.H{"error": "Failed to like comment"})
		return
	}

	c.JSON(200, gin.H{"message": "Comment liked successfully"})
}

// 修改 handleUnlike 函数
func handleUnlike(c *gin.Context) {
	commentID, err := primitive.ObjectIDFromHex(c.Param("id"))
	if err != nil {
		c.JSON(400, gin.H{"error": "Invalid comment ID"})
		return
	}

	userID, _ := c.Get("user_id")
	collection := client.Database("forum").Collection("comments")

	// 移除点赞
	result, err := collection.UpdateOne(
		context.TODO(),
		bson.M{"_id": commentID},
		bson.M{
			"$pull": bson.M{
				"likes": userID.(primitive.ObjectID),
			},
		},
	)

	if err != nil {
		log.Printf("Error removing like: %v", err)
		c.JSON(500, gin.H{"error": "Failed to unlike comment"})
		return
	}

	if result.ModifiedCount == 0 {
		c.JSON(400, gin.H{"error": "Comment not found or not liked"})
		return
	}

	c.JSON(200, gin.H{"message": "Comment unliked successfully"})
}
