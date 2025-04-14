package main

import (
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

// Cấu trúc Note
type Note struct {
	Id           int        `json:"id" gorm:"column:id;"`
	DetailedNote string     `json:"detailed_note" gorm:"column:detailed_note;"`
	UserId       int        `json:"user_id" gorm:"column:user_id;"`
	CreatedAt    *time.Time `json:"created_at" gorm:"column:created_at;"`
	UpdatedAt    *time.Time `json:"updated_at" gorm:"column:updated_at;"`
}

// Cấu trúc User
type User struct {
	Id          int        `json:"id" gorm:"column:id;"`
	Username    string     `json:"username" gorm:"column:username;"`
	Password    string     `json:"password" gorm:"column:password;"`
	CreatedAt   *time.Time `json:"created_at" gorm:"column:created_at;"`
	UpdatedAt   *time.Time `json:"updated_at" gorm:"column:updated_at;"`
	Plan        string     `json:"plan" gorm:"column:plan;default:nor"`
	LimitPerDay int        `json:"limit_per_day" gorm:"column:limit_per_day; default:5"`
}

// Claims structure cho JWT
type Claims struct { // tạo struct cho jwt
	UserId               int `json:"user_id"`
	jwt.RegisteredClaims     // cái này chạy để cho nó tạo tụ đông những cái cần thiết
}

func (Note) TableName() string { return "notes" } // struct này tương ứng váo bảng nào
func (User) TableName() string { return "users" }

var jwtKey = []byte(os.Getenv("JWT_SECRET_KEY")) // Sử dụng biến môi trường cho secret key. Tức là lấy key để ký

func main() {
	dsn := "root:@tcp(127.0.0.1:3306)/todo?charset=utf8mb4&parseTime=True&loc=Local" // thông tin kết nối db
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})                            // lệnh kết nối db
	if err != nil {
		log.Fatalln("Cannot connect to MySQL:", err) // có lỗi in ra ko kết nối đc
	}
	log.Println("Connected to MySQL:", db)

	router := gin.Default()

	// Middleware CORS
	router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "http://127.0.0.1:5500") //  cho cổng 5500 gọi api
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")
		c.Writer.Header().Set("Access-Control-Max-Age", "86400")

		if c.Request.Method == "OPTIONS" { // chỉ khác cổng nó mới gửi request kiểu option này, trả về http.StatusNoContent có nghĩaa là đồng ý cho cổng khác gọi api
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	})

	// Nhóm route không cần đăng nhập vào
	public := router.Group("/v1")
	{
		public.POST("/register", register(db))
		public.POST("/login", login(db))
	}

	// Nhóm route cần đăng nhập
	auth := router.Group("/v1")
	auth.Use(authMiddleware()) // Áp dụng middleware cho tất cả route trong nhóm này
	{
		auth.POST("/notes", createNote(db))
		auth.GET("/notes", getListOfNotes(db))
		auth.GET("/notes/:id", readNoteById(db))
		auth.PUT("/notes/:id", editNoteById(db))
		auth.DELETE("/notes/:id", deleteNoteById(db))
		auth.GET("/me", getCurrentUser(db)) // Endpoint mới để lấy thông tin user hiện tại
	}

	router.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	log.Println("Starting server on :8080")
	router.Run(":8080") // chạy server ở cổng 8080
}

// Middleware xác thực JWT
func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Lấy token từ header Authorization
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			return
		}

		// Kiểm tra định dạng "Bearer <token>"
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		if tokenString == authHeader {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid authorization format"})
			return
		}

		// Parse và validate token
		claims := &Claims{}
		token, err := jwt.ParseWithClaims(tokenString, claims, func(token *jwt.Token) (interface{}, error) {
			return jwtKey, nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid token"})
			return
		}

		// Lưu user_id vào context để sử dụng trong các handler. context là đối tượng chứa mọi thông tin của request hay repo
		c.Set("user_id", claims.UserId)
		c.Next()
	}
}

// Hàm đăng ký user mới
func register(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var user User
		if err := c.ShouldBind(&user); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Kiểm tra username đã tồn tại chưa
		var existingUser User
		if err := db.Where("username = ?", user.Username).First(&existingUser).Error; err == nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Username already exists"})
			return
		}

		// Tạo user mới
		if err := db.Create(&user).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"data": user.Id})
	}
}

// Hàm đăng nhập và trả về JWT
func login(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		var credentials struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}

		if err := c.ShouldBind(&credentials); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Tìm user trong database
		var user User
		if err := db.Where("username = ?", credentials.Username).First(&user).Error; err != nil {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
			return
		}

		// Kiểm tra password (trong thực tế nên so sánh hash)
		if user.Password != credentials.Password {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Invalid username or password"})
			return
		}

		// Tạo JWT token
		expirationTime := time.Now().Add(24 * time.Hour)
		claims := &Claims{
			UserId: user.Id,
			RegisteredClaims: jwt.RegisteredClaims{
				ExpiresAt: jwt.NewNumericDate(expirationTime),
			},
		}

		token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
		tokenString, err := token.SignedString(jwtKey)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to generate token"})
			return
		}

		// Trả về token cho client
		c.JSON(http.StatusOK, gin.H{
			"token":     tokenString,
			"expiresAt": expirationTime.Unix(),
			"user_id":   user.Id,
		})
	}
}

// Hàm lấy thông tin user hiện tại
func getCurrentUser(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID, exists := c.Get("user_id")
		if !exists {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "User not authenticated"})
			return
		}

		var user User
		if err := db.First(&user, userID).Error; err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "User not found"})
			return
		}

		// Không trả về password
		user.Password = ""
		c.JSON(http.StatusOK, gin.H{"data": user})
	}
}

// Các hàm xử lý note

func createNote(db *gorm.DB) gin.HandlerFunc { // tạo note, và kiểm tra giới hạn. Thỏa mã điều kiện mới cho tạo
	return func(c *gin.Context) {
		userID := c.MustGet("user_id").(int)

		// Lấy thông tin user để kiểm tra limit_per_day
		var user User // khai báo biến user kiểu struct User
		if err := db.First(&user, userID).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user information"}) // http.StatusInternalServerError: mã lỗi 500- lỗi server
			return
		}

		// Kiểm tra giới hạn nếu limit_per_day, chỉ kiểm tra khi nó > 0
		if user.LimitPerDay > 0 {
			// Tính số todo đã tạo trong ngày
			var count int64
			today := time.Now().Format("2006-01-02") // lấy ngày hôm nay
			if err := db.Model(&Note{}).             // chọn bảng notes để truy vấn (Note là struct của bảng notes)
									Where("user_id = ? AND DATE(created_at) = ?", userID, today). // đếm số xuất hiện user_id trong ngày hôm nay (today)
									Count(&count).Error; err != nil {                             // đếm rồi lưu vào count
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count today's notes"}) // gin.H{"error": "Failed to count today's notes"} sẽ trả về JSON {"error": "Failed to count today's notes"}
				return
			}

			// Kiểm tra giới hạn
			if count >= int64(user.LimitPerDay) { // nếu todo tạo hôm nay >= limit thì trả về
				c.JSON(http.StatusForbidden, gin.H{ // tạo 1 json trả về bên frontend trong thông báo một JSON chưa các key và value, khi bên backend thấy vượt quá giới hạn, sẽ gửi json này cho bên frontend để in ra  những thứ được ghi trong json này
					"error": "You have reached your daily limit for creating notes",
					"limit": user.LimitPerDay, // giới hạn
					"used":  count,            // đã tạo hôm nay
				})
				return
			}
		}

		var dataNote Note                               // khai báo biến dataNote từ kiểu dữ liệu  Note (Note là 1 struct)
		if err := c.ShouldBind(&dataNote); err != nil { // ShouldBind đưa dữ liệu từ body request vào dataNote, từ trong JSON gán vào các trường tương ứng bên trong
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}) // http.StatusBadRequest lỗi 400, gửi request không hợp lệ
			return
		}

		dataNote.DetailedNote = strings.TrimSpace(dataNote.DetailedNote) // strings.TrimSpace() là hàm trong Go để xóa các khoảng trắng (dấu cách, tab, xuống dòng) ở đầu và cuối chuỗi.
		if dataNote.DetailedNote == "" {                                 // nếu DetailedNote, cái mình nhập vào mà trống thì báo không được trống
			c.JSON(http.StatusBadRequest, gin.H{"error": "detailed_note cannot be blank"})
			return
		}

		dataNote.UserId = userID

		if err := db.Create(&dataNote).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"data": dataNote.Id})
	}
}

func getListOfNotes(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.MustGet("user_id").(int) // Lấy user_id từ context

		type DataPaging struct {
			Page  int   `json:"page" form:"page"`
			Limit int   `json:"limit" form:"limit"`
			Total int64 `json:"total" form:"-"`
		}

		var paging DataPaging
		if err := c.ShouldBind(&paging); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if paging.Page <= 0 {
			paging.Page = 1
		}

		if paging.Limit <= 0 {
			paging.Limit = 10
		}

		offset := (paging.Page - 1) * paging.Limit
		var result []Note

		// Chỉ lấy notes của user hiện tại
		if err := db.Table(Note{}.TableName()).
			Where("user_id = ?", userID).
			Count(&paging.Total).
			Offset(offset).
			Order("id desc").
			Find(&result).Error; err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"data": result})
	}
}

// Các hàm readNoteById, editNoteById, deleteNoteById cũng cần sửa để kiểm tra user_id
// (Tương tự như các hàm trên, chỉ thêm điều kiện Where("user_id = ?", userID))
func readNoteById(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Lấy user_id từ JWT token
		userID := c.MustGet("user_id").(int)

		// Lấy id từ URL parameter
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid note ID"})
			return
		}

		var dataNote Note

		// Tìm note với điều kiện: id phải khớp VÀ user_id phải khớp với user đang đăng nhập
		if err := db.Where("id = ? AND user_id = ?", id, userID).First(&dataNote).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(http.StatusNotFound, gin.H{
					"error": "Note not found or you don't have permission to access it",
				})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			}
			return
		}

		c.JSON(http.StatusOK, gin.H{"data": dataNote})
	}
}
func editNoteById(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Lấy user_id từ JWT token
		userID := c.MustGet("user_id").(int)

		// Lấy id từ URL parameter
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid note ID"})
			return
		}

		// Kiểm tra note có tồn tại và thuộc về user này không
		var existingNote Note
		if err := db.Where("id = ? AND user_id = ?", id, userID).First(&existingNote).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(http.StatusNotFound, gin.H{
					"error": "Note not found or you don't have permission to edit it",
				})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			}
			return
		}

		// Bind dữ liệu từ request
		var dataNote Note
		if err := c.ShouldBind(&dataNote); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		// Validate dữ liệu
		dataNote.DetailedNote = strings.TrimSpace(dataNote.DetailedNote)
		if dataNote.DetailedNote == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "detailed_note cannot be blank"})
			return
		}

		// Chỉ cập nhật các trường được phép (không cho phép thay đổi user_id)
		updateData := map[string]interface{}{
			"detailed_note": dataNote.DetailedNote,
			"updated_at":    time.Now(),
		}

		// Thực hiện update với điều kiện id và user_id
		if err := db.Model(&Note{}).
			Where("id = ? AND user_id = ?", id, userID).
			Updates(updateData).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"data": true})
	}
}
func deleteNoteById(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		// Lấy user_id từ JWT token
		userID := c.MustGet("user_id").(int)

		// Lấy id từ URL parameter
		id, err := strconv.Atoi(c.Param("id"))
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid note ID"})
			return
		}

		// Kiểm tra note có tồn tại và thuộc về user này không
		var existingNote Note
		if err := db.Where("id = ? AND user_id = ?", id, userID).First(&existingNote).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				c.JSON(http.StatusNotFound, gin.H{
					"error": "Note not found or you don't have permission to delete it",
				})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			}
			return
		}

		// Thực hiện xóa với điều kiện id và user_id
		if err := db.Where("id = ? AND user_id = ?", id, userID).Delete(&Note{}).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"data": true})
	}
}
