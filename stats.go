package main

import (
	"context"
	"log"
	"time"

	"github.com/gin-gonic/gin"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// 获取社区统计信息
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

	// 获取总帖子数
	stats.TotalPosts, _ = postsCollection.CountDocuments(context.TODO(), bson.M{})

	// 获取总用户数
	stats.TotalUsers, _ = usersCollection.CountDocuments(context.TODO(), bson.M{})

	// 获取总评论数
	stats.TotalComments, _ = commentsCollection.CountDocuments(context.TODO(), bson.M{})

	// 获取活跃用户数（30天内发帖的用户）
	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
	stats.ActiveUsers, _ = postsCollection.CountDocuments(context.TODO(), bson.M{
		"created_at": bson.M{"$gte": thirtyDaysAgo},
	})

	c.JSON(200, stats)
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
		{{Key: "$lookup", Value: bson.M{
			"from":         "users",
			"localField":   "_id",
			"foreignField": "_id",
			"as":           "user_info",
		}}},
		{{Key: "$unwind", Value: bson.M{
			"path":                       "$user_info",
			"preserveNullAndEmptyArrays": true,
		}}},
		{{Key: "$project", Value: bson.M{
			"_id":        1,
			"username":   1,
			"post_count": 1,
			"avatar":     "$user_info.avatar",
			"bio":        "$user_info.bio",
		}}},
	}

	cursor, err := collection.Aggregate(context.TODO(), pipeline)
	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to fetch user ranking"})
		return
	}

	var rankings []struct {
		ID        string `bson:"_id" json:"_id"`
		Username  string `bson:"username" json:"username"`
		PostCount int    `bson:"post_count" json:"post_count"`
		Avatar    string `bson:"avatar" json:"avatar"`
		Bio       string `bson:"bio" json:"bio"`
	}

	if err = cursor.All(context.TODO(), &rankings); err != nil {
		c.JSON(500, gin.H{"error": "Failed to decode rankings"})
		return
	}

	c.JSON(200, rankings)
}

// 获取帖子排名
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
		log.Printf("Error fetching post ranking: %v", err)
		c.JSON(500, gin.H{"error": "Failed to fetch post ranking"})
		return
	}

	var posts []Post
	if err = cursor.All(context.TODO(), &posts); err != nil {
		log.Printf("Error decoding posts: %v", err)
		c.JSON(500, gin.H{"error": "Failed to decode posts"})
		return
	}

	c.JSON(200, posts)
}

// 获取热门帖子
func getPopularPosts(c *gin.Context) {
	collection := client.Database("forum").Collection("posts")
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
		c.JSON(500, gin.H{"error": "Failed to fetch popular posts"})
		return
	}

	var posts []Post
	if err = cursor.All(context.TODO(), &posts); err != nil {
		c.JSON(500, gin.H{"error": "Failed to decode posts"})
		return
	}

	c.JSON(200, posts)
}

// 获取未读消息数量
func getUnreadCount(c *gin.Context) {
	userID, _ := c.Get("user_id")
	collection := client.Database("forum").Collection("messages")

	count, err := collection.CountDocuments(
		context.TODO(),
		bson.M{
			"to_id":   userID.(string),
			"is_read": false,
		},
	)

	if err != nil {
		c.JSON(500, gin.H{"error": "Failed to get unread count"})
		return
	}

	c.JSON(200, gin.H{"count": count})
}

// 获取所有分类
func getCategories(c *gin.Context) {
	// 这里可以从数据库中获取分类，或者直接返回预定义的分类列表
	categories := []string{
		"技术",
		"生活",
		"闲聊",
		"分享",
		"其他",
	}
	c.JSON(200, categories)
}
