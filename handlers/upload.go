// handlers/upload.go
package handlers

import (
	"fmt"
	"path/filepath"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

func HandleFileUpload(c *gin.Context) {
	// 获取文件
	file, err := c.FormFile("image")
	if err != nil {
		c.JSON(400, gin.H{"error": "无法获取文件"})
		return
	}

	// 验证文件大小（5MB）
	if file.Size > 5*1024*1024 {
		c.JSON(400, gin.H{"error": "文件大小不能超过5MB"})
		return
	}

	// 验证文件类型
	ext := filepath.Ext(file.Filename)
	if ext != ".jpg" && ext != ".jpeg" && ext != ".png" && ext != ".gif" {
		c.JSON(400, gin.H{"error": "只支持jpg、jpeg、png、gif格式的图片"})
		return
	}

	// 生成唯一文件名
	filename := uuid.New().String() + ext
	filepath := fmt.Sprintf("uploads/%s", filename)

	// 保存文件
	if err := c.SaveUploadedFile(file, filepath); err != nil {
		c.JSON(500, gin.H{"error": "文件保存失败"})
		return
	}

	// 返回文件URL
	c.JSON(200, gin.H{
		"url": fmt.Sprintf("/uploads/%s", filename),
	})
}