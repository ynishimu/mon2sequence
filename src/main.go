package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"mon2seq"
	"net/http"
	"os"
	"path/filepath"
)

func main() {
	router := gin.Default()
	// Set a lower memory limit for multipart forms (default is 32 MiB)
	router.MaxMultipartMemory = 8 << 20 // 8 MiB
	router.Static("/", "./public")
	router.POST("/mon2seq", func(c *gin.Context) {
		name := c.PostForm("hostname")

		// Source
		file, err := c.FormFile("file")
		if err != nil {
			c.String(http.StatusBadRequest, fmt.Sprintf("get form err: %s", err.Error()))
			return
		}

		//for local test, change it to ./
		filename := "/tmp/" + filepath.Base(file.Filename)
		if err := c.SaveUploadedFile(file, filename); err != nil {
			c.String(http.StatusBadRequest, fmt.Sprintf("upload file err: %s", err.Error()))
			return
		}

		diagfile_path := mon2seq.Monparse(name, filename)

		header := c.Writer.Header()
		header["Content-type"] = []string{"application/octet-stream"}
		header["Content-Disposition"] = []string{"attachment; filename= " + diagfile_path}
		file2, err2 := os.Open(diagfile_path)
		if err2 != nil {
			c.String(http.StatusOK, "%v", err2)
			return
		}
		defer file2.Close()

		io.Copy(c.Writer, file2)
	})
	router.Run(":8090")
}
