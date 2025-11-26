package main

import (
	"crypto/rand"
	"crypto/sha256"
	"embed"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log"
	"math"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

//go:embed web
var embeddedWeb embed.FS

type UserData struct {
	Username     string    `json:"username"`
	PasswordHash string    `json:"passwordHash"`
	LastActive   time.Time `json:"lastActive"`
}

type Message struct {
	ID        string    `json:"id"`
	Username  string    `json:"username"`
	Content   string    `json:"content"`
	Kind      string    `json:"kind"`
	FileURL   string    `json:"fileUrl,omitempty"`
	FileName  string    `json:"fileName,omitempty"`
	CreatedAt time.Time `json:"createdAt"`
}

type outgoingPayload struct {
	Type     string    `json:"type"`
	Message  *Message  `json:"message,omitempty"`
	Messages []Message `json:"messages,omitempty"`
	Users    []string  `json:"users,omitempty"`
	Online   int       `json:"online,omitempty"`
	Error    string    `json:"error,omitempty"`
}

type Server struct {
	mu            sync.Mutex
	messages      []Message
	clients       map[*Client]struct{}
	userSessions  map[string]string // sessionToken -> username
	onlineCounts  map[string]int
	lastMessageAt map[string]time.Time
}

type Client struct {
	username string
	send     chan outgoingPayload
	closeCh  chan struct{}
}

func main() {
	if err := os.MkdirAll("files/users", 0o755); err != nil {
		log.Fatalf("failed creating users dir: %v", err)
	}

	srv := &Server{
		messages:      []Message{},
		clients:       map[*Client]struct{}{},
		userSessions:  map[string]string{},
		onlineCounts:  map[string]int{},
		lastMessageAt: map[string]time.Time{},
	}

	go srv.cleanupLoop()
	go srv.userCleanupLoop()

	mux := http.NewServeMux()
	mux.HandleFunc("/register", srv.handleRegister)
	mux.HandleFunc("/login", srv.handleLogin)
	mux.HandleFunc("/logout", srv.handleLogout)
	mux.HandleFunc("/me", srv.handleMe)
	mux.HandleFunc("/upload", srv.handleUpload)
	mux.HandleFunc("/message", srv.handleMessage)
	mux.HandleFunc("/stream", srv.handleStream)

	webFS, _ := fs.Sub(embeddedWeb, "web")
	fileServer := http.FileServer(http.FS(webFS))
	mux.Handle("/assets/", http.StripPrefix("/", fileServer))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		index, err := webFS.Open("index.html")
		if err != nil {
			http.Error(w, "index not found", http.StatusInternalServerError)
			return
		}
		defer index.Close()
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.Copy(w, index)
	})

	mux.Handle("/files/", http.StripPrefix("/files/", http.HandlerFunc(serveFiles)))

	portFlag := flag.String("port", "", "port to listen on")
	shortPort := flag.String("p", "", "port to listen on")
	flag.Parse()

	port := firstNonEmpty(*portFlag, *shortPort, os.Getenv("PORT"))
	if port == "" {
		port = "8080"
	}

	srvAddr := fmt.Sprintf(":%s", port)
	log.Printf("nexio listening on %s", srvAddr)
	if err := http.ListenAndServe(srvAddr, mux); err != nil {
		log.Fatalf("server error: %v", err)
	}
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		Username        string `json:"username"`
		Password        string `json:"password"`
		PasswordConfirm string `json:"passwordConfirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	if err := validateCredentials(payload.Username, payload.Password, payload.PasswordConfirm); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if _, err := os.Stat(userDataPath(payload.Username)); err == nil {
		http.Error(w, "user already exists", http.StatusConflict)
		return
	}

	if err := saveUser(UserData{
		Username:     payload.Username,
		PasswordHash: hashString(payload.Password),
		LastActive:   time.Now(),
	}); err != nil {
		http.Error(w, "failed to save user", http.StatusInternalServerError)
		return
	}

	token := s.startSession(payload.Username)
	setSessionCookie(w, token)
	w.WriteHeader(http.StatusCreated)
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	if !validateUsername(payload.Username) {
		http.Error(w, "invalid username", http.StatusBadRequest)
		return
	}

	user, err := loadUser(payload.Username)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	if user.PasswordHash != hashString(payload.Password) {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}

	user.LastActive = time.Now()
	_ = saveUser(user)

	token := s.startSession(payload.Username)
	setSessionCookie(w, token)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	token, _ := readSessionCookie(r)
	if token != "" {
		s.mu.Lock()
		delete(s.userSessions, token)
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:    "session",
		Value:   "",
		Path:    "/",
		Expires: time.Now().Add(-time.Hour),
	})
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	username := s.usernameFromRequest(r)
	if username == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"username": username})
}

func (s *Server) handleMessage(w http.ResponseWriter, r *http.Request) {
	username := s.usernameFromRequest(r)
	if username == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var payload struct {
		Content string `json:"content"`
	}
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		http.Error(w, "invalid payload", http.StatusBadRequest)
		return
	}

	msg := Message{
		ID:        generateID(),
		Username:  username,
		Content:   strings.TrimSpace(payload.Content),
		Kind:      "text",
		CreatedAt: time.Now(),
	}
	if msg.Content == "" {
		http.Error(w, "empty message", http.StatusBadRequest)
		return
	}

	if err := s.appendMessage(msg); err != nil {
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	}

	s.broadcast(outgoingPayload{Type: "message", Message: &msg})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(msg)
}

func (s *Server) handleUpload(w http.ResponseWriter, r *http.Request) {
	username := s.usernameFromRequest(r)
	if username == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	if err := r.ParseMultipartForm(128 << 20); err != nil {
		http.Error(w, "failed to parse form", http.StatusBadRequest)
		return
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		http.Error(w, "file is required", http.StatusBadRequest)
		return
	}
	defer file.Close()

	if header.Size > 128<<20 {
		http.Error(w, "file too large", http.StatusBadRequest)
		return
	}

	asImage := strings.HasPrefix(header.Header.Get("Content-Type"), "image/")

	storedPath, fileURL, err := saveUploadedFile(file, header)
	if err != nil {
		log.Printf("upload error: %v", err)
		http.Error(w, "failed to save file", http.StatusInternalServerError)
		return
	}

	msgKind := "file"
	if asImage {
		msgKind = "image"
	}

	msg := Message{
		ID:        generateID(),
		Username:  username,
		Content:   "",
		Kind:      msgKind,
		FileURL:   fileURL,
		FileName:  header.Filename,
		CreatedAt: time.Now(),
	}

	if err := s.appendMessage(msg); err != nil {
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	}

	s.broadcast(outgoingPayload{Type: "message", Message: &msg})
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(msg)

	go func(path string, created time.Time) {
		<-time.After(time.Until(created.Add(2 * time.Hour)))
		os.Remove(path)
		os.RemoveAll(filepath.Dir(path))
	}(storedPath, msg.CreatedAt)
}

func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	username := s.usernameFromRequest(r)
	if username == "" {
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "stream unsupported", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	client := &Client{
		username: username,
		send:     make(chan outgoingPayload, 10),
		closeCh:  make(chan struct{}),
	}

	s.registerClient(client)
	defer s.unregisterClient(client)

	sendEvent(w, outgoingPayload{Type: "history", Messages: s.recentMessages()})
	flusher.Flush()

	notify := r.Context().Done()
	go func() {
		<-notify
		close(client.closeCh)
	}()

	for {
		select {
		case payload := <-client.send:
			sendEvent(w, payload)
			flusher.Flush()
		case <-client.closeCh:
			return
		}
	}
}

func sendEvent(w http.ResponseWriter, payload outgoingPayload) {
	raw, _ := json.Marshal(payload)
	fmt.Fprintf(w, "data: %s\n\n", string(raw))
}

func (s *Server) registerClient(c *Client) {
	s.mu.Lock()
	s.clients[c] = struct{}{}
	s.onlineCounts[c.username]++
	users := s.onlineUsernames()
	s.mu.Unlock()
	s.broadcast(outgoingPayload{Type: "online", Users: users, Online: len(users)})
}

func (s *Server) unregisterClient(c *Client) {
	s.mu.Lock()
	if _, ok := s.clients[c]; ok {
		delete(s.clients, c)
		s.onlineCounts[c.username]--
		if s.onlineCounts[c.username] <= 0 {
			delete(s.onlineCounts, c.username)
		}
	}
	users := s.onlineUsernames()
	s.mu.Unlock()
	s.broadcast(outgoingPayload{Type: "online", Users: users, Online: len(users)})
}

func (s *Server) appendMessage(msg Message) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	last, ok := s.lastMessageAt[msg.Username]
	if ok && time.Since(last) < time.Second {
		return errors.New("请等待1秒再发送下一条消息")
	}
	s.lastMessageAt[msg.Username] = time.Now()

	s.messages = append(s.messages, msg)
	if len(s.messages) > 500 {
		s.messages = s.messages[len(s.messages)-500:]
	}
	go updateUserActivity(msg.Username)
	return nil
}

func (s *Server) broadcast(payload outgoingPayload) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for c := range s.clients {
		select {
		case c.send <- payload:
		default:
		}
	}
}

func (s *Server) recentMessages() []Message {
	const historyLimit = 100
	start := 0
	if len(s.messages) > historyLimit {
		start = len(s.messages) - historyLimit
	}
	res := make([]Message, len(s.messages[start:]))
	copy(res, s.messages[start:])
	return res
}

func (s *Server) onlineUsernames() []string {
	users := make([]string, 0, len(s.onlineCounts))
	for u := range s.onlineCounts {
		users = append(users, u)
	}
	return users
}

func (s *Server) usernameFromRequest(r *http.Request) string {
	token, err := readSessionCookie(r)
	if err != nil {
		return ""
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.userSessions[token]
}

func (s *Server) startSession(username string) string {
	s.mu.Lock()
	defer s.mu.Unlock()
	token := randomHex(32)
	s.userSessions[token] = username
	return token
}

func setSessionCookie(w http.ResponseWriter, token string) {
	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		Expires:  time.Now().Add(30 * 24 * time.Hour),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func readSessionCookie(r *http.Request) (string, error) {
	c, err := r.Cookie("session")
	if err != nil {
		return "", err
	}
	return c.Value, nil
}

func userDataPath(username string) string {
	return filepath.Join("files", "users", username, "data.json")
}

func saveUser(data UserData) error {
	path := userDataPath(data.Username)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func loadUser(username string) (UserData, error) {
	var data UserData
	raw, err := os.ReadFile(userDataPath(username))
	if err != nil {
		return data, err
	}
	if err := json.Unmarshal(raw, &data); err != nil {
		return data, err
	}
	return data, nil
}

func validateCredentials(username, password, confirm string) error {
	if !validateUsername(username) {
		return errors.New("用户名需为5-15位字母或数字")
	}
	if password != confirm {
		return errors.New("两次密码输入不一致")
	}
	if err := validatePassword(password); err != nil {
		return err
	}
	return nil
}

func validateUsername(username string) bool {
	re := regexp.MustCompile(`^[A-Za-z0-9]{5,15}$`)
	return re.MatchString(username)
}

func validatePassword(password string) error {
	if len(password) < 6 || len(password) > 32 {
		return errors.New("密码长度需为6-32位")
	}
	categories := 0
	if regexp.MustCompile(`[a-z]`).MatchString(password) {
		categories++
	}
	if regexp.MustCompile(`[A-Z]`).MatchString(password) {
		categories++
	}
	if regexp.MustCompile(`[0-9]`).MatchString(password) {
		categories++
	}
	if regexp.MustCompile(`[^A-Za-z0-9]`).MatchString(password) {
		categories++
	}
	if categories < 2 {
		return errors.New("密码需包含至少两种字符组合")
	}
	return nil
}

func hashString(v string) string {
	sum := sha256.Sum256([]byte(v))
	return hex.EncodeToString(sum[:])
}

func randomHex(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func generateID() string {
	return fmt.Sprintf("%d-%s", time.Now().UnixNano(), randomHex(4))
}

func saveUploadedFile(file multipart.File, header *multipart.FileHeader) (string, string, error) {
	temp, err := os.CreateTemp("", "upload-*")
	if err != nil {
		return "", "", err
	}
	defer os.Remove(temp.Name())

	hash := sha256.New()
	writer := io.MultiWriter(temp, hash)
	if _, err := io.Copy(writer, file); err != nil {
		temp.Close()
		return "", "", err
	}
	temp.Close()

	shaHex := hex.EncodeToString(hash.Sum(nil))
	dir := filepath.Join("files", shaHex)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", "", err
	}
	encodedName := base64.StdEncoding.EncodeToString([]byte(header.Filename))
	finalPath := filepath.Join(dir, encodedName)
	if err := os.Rename(temp.Name(), finalPath); err != nil {
		return "", "", err
	}

	return finalPath, fmt.Sprintf("/files/%s/%s", shaHex, encodedName), nil
}

func serveFiles(w http.ResponseWriter, r *http.Request) {
	path := filepath.Clean(r.URL.Path)
	if strings.Contains(path, "..") {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	fullPath := filepath.Join("files", path)
	http.ServeFile(w, r, fullPath)
}

func (s *Server) cleanupLoop() {
	ticker := time.NewTicker(1 * time.Minute)
	for range ticker.C {
		s.pruneMessages()
	}
}

func (s *Server) pruneMessages() {
	s.mu.Lock()
	cutoff := time.Now().Add(-2 * time.Hour)
	filtered := s.messages[:0]
	for _, msg := range s.messages {
		if msg.CreatedAt.After(cutoff) {
			filtered = append(filtered, msg)
		} else {
			if msg.FileURL != "" {
				go removeFileForMessage(msg)
			}
		}
	}
	s.messages = filtered
	s.mu.Unlock()
}

func removeFileForMessage(msg Message) {
	parts := strings.Split(strings.TrimPrefix(msg.FileURL, "/files/"), "/")
	if len(parts) < 2 {
		return
	}
	fullPath := filepath.Join("files", parts[0], parts[1])
	os.Remove(fullPath)
	os.RemoveAll(filepath.Dir(fullPath))
}

func (s *Server) userCleanupLoop() {
	ticker := time.NewTicker(12 * time.Hour)
	for range ticker.C {
		pruneInactiveUsers()
	}
}

func pruneInactiveUsers() {
	base := filepath.Join("files", "users")
	entries, err := os.ReadDir(base)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-24 * 24 * time.Hour)
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		dataPath := filepath.Join(base, e.Name(), "data.json")
		raw, err := os.ReadFile(dataPath)
		if err != nil {
			continue
		}
		var u UserData
		if err := json.Unmarshal(raw, &u); err != nil {
			continue
		}
		if u.LastActive.Before(cutoff) {
			os.RemoveAll(filepath.Join(base, e.Name()))
		}
	}
}

func updateUserActivity(username string) {
	user, err := loadUser(username)
	if err != nil {
		return
	}
	user.LastActive = time.Now()
	_ = saveUser(user)
}

func passwordStrengthScore(password string) int {
	lengthScore := math.Min(float64(len(password))*5, 40)
	variety := 0
	if regexp.MustCompile(`[a-z]`).MatchString(password) {
		variety++
	}
	if regexp.MustCompile(`[A-Z]`).MatchString(password) {
		variety++
	}
	if regexp.MustCompile(`[0-9]`).MatchString(password) {
		variety++
	}
	if regexp.MustCompile(`[^A-Za-z0-9]`).MatchString(password) {
		variety++
	}
	varietyScore := float64(variety) * 15
	return int(math.Min(100, lengthScore+varietyScore))
}
