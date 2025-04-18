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

func createNote(db *gorm.DB) gin.HandlerFunc {
	return func(c *gin.Context) {
		userID := c.MustGet("user_id").(int) // c.MustGet("user_id") lấy user id từ context (cái chứa tất cả thông tin của  request/response)
		// lấy từ c bởi khi hàm authMiddleware() chạy rồi xác thực token thì nó lưu user_id vào context
		// có thể nói dùng context truyền data của JWT
		// c.Set("user_id", claims.UserId), Gin lưu giá trị vào context dưới dạng interface{} chứ ko phải int
		// nên khi lấy ra bằng c.Get() hoặc c.MustGet(), Go trả về interface{} chứ không phải kiểu gốc=> phải ép kiểu bằng .(int)
		// interface{} là một kiểu dữ liệu đặc biệt, đóng vai trò như một "container" có thể chứa mọi giá trị thuộc bất kỳ kiểu dữ liệu nào.

		// Transaction
		tx := db.Begin()     // bắt đầu 1 transaction
		if tx.Error != nil { // nếu khởi tạo tx lỗi thfi trả về JSON bên dưới rồi kết thcú
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to start transaction"})
			return
		}

		// Lấy thông tin user với lock để tránh race condition
		var user User                                                                                // kha báo user từ struct User
		if err := tx.Set("gorm:query_option", "FOR UPDATE").First(&user, userID).Error; err != nil { /* FOR UPDATE: khóa bản ghi lại, các transaction khác muốn đọc hay ghi
			    phải chờ transaction trước kết thúc mới có thể đọc hay ghi được
				tx.Set("gorm:query_option", "FOR UPDATE").First(&user, userID) -> SELECT * FROM users WHERE id = [userID] FOR UPDATE LIMIT 1
				First(&user, userID) sẽ chuyển thành WHERE id = [userID] */
			tx.Rollback() // Rollback khi mà có lỗi ở câu lệnh bên trên và trả về lỗi server 500 kèm json lỗi bên dưới. sau đso kết thúc
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get user information"})
			return
		}

		// Kiểm tra giới hạn nếu limit_per_day > 0
		if user.LimitPerDay > 0 {
			// Tính số todo đã tạo trong ngày
			var count int64
			today := time.Now().Format("2006-01-02")
			if err := tx.Model(&Note{}). /* ở đây dùng transacton khi truy vấn bảng notes để:
				Lỡ 2 request gửi tới 1 lúc, mà cái đầu nó chưa tạo note xong -> 2 cái đều đọc đc điều kiện là 4 -> bé hơn 5
				=> nó tạo 2 cái luôn thành ra một ngày dã tạo 6 cái note
				Nhưng do bên trên đã dùng transaction conngj thêm For Update nên chuyện cái thứ 2 cũng nhảy vào đọc được là không thể
				-> ngăn chặn chuyện tạo được note thứ 6 */

				Where("user_id = ? AND DATE(created_at) = ?", userID, today). // đếm của user hiện tại được lưu trong context và ngày hiện tại
				Count(&count).Error; err != nil {                             // đếm và gán vào count, nếu có lỗi gì thì Rollback và báo lỗi 500 kèm json bên dưới
				tx.Rollback()
				c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to count today's notes"})
				return // kết thúc
			}

			// Kiểm tra giới hạn
			if count >= int64(user.LimitPerDay) {
				tx.Rollback() // nếu lớn hơn thì Rollback xong trả về json
				c.JSON(http.StatusForbidden, gin.H{
					"error": "You have reached your daily limit for creating notes",
					"limit": user.LimitPerDay,
					"used":  count,
				})
				return
			}
		}

		var dataNote Note                               // tạo dataNote từ struct Note
		if err := c.ShouldBind(&dataNote); err != nil { // dán dữ liệu từ request body vào dataNote, nếu có lỗi thì
			tx.Rollback()
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		dataNote.DetailedNote = strings.TrimSpace(dataNote.DetailedNote) // xóa khoảng trắng thừa
		if dataNote.DetailedNote == "" {                                 // kiểm tra nếu không ghi nội dung note thì Rollback và trả json
			tx.Rollback()
			c.JSON(http.StatusBadRequest, gin.H{"error": "detailed_note cannot be blank"})
			return
		}

		dataNote.UserId = userID // gán user id cho note này

		if err := tx.Create(&dataNote).Error; err != nil { // lưu vào database, thực hiện lệnh insert và lưu kết quả vào transaction log
			tx.Rollback()                                              // nếu có lỗi
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()}) //err.Error() trả về chuối mô tả lỗi
			return
		}

		// Commit transaction nếu bên trên chạy mượt không lỗi gì
		if err := tx.Commit().Error; err != nil { // xác nhận transaction thành công, lưu tất cả thay đổi vào database nếu không có lỗi
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to commit transaction"})
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
