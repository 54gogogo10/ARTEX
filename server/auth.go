package server

import (
	"crypto/rand"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/golang-jwt/jwt/v5"
	"golang.org/x/crypto/bcrypt"
)

const (
	jwtKeyFilename = "jwt.key"
	authPassKey    = "auth.password_hash"
	jwtTTL         = 7 * 24 * time.Hour
	keyChars       = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

	// 下限与 setup 页的前端校验一致——校验只放在前端等于没放，直接打 API 就能
	// 绕过。上限是 bcrypt 的硬限制：超过 72 字节 GenerateFromPassword 会返回
	// ErrPasswordTooLong，提前挡掉好过让用户收到一句含义不明的「密码加密失败」。
	minPasswordRunes = 8
	maxPasswordBytes = 72
)

// errDataSourceUnavailable 是密码相关读操作失败时统一的回复。这些 handler 绝不能
// 把"读不到"当成"没有设置"：authInit 曾因此在数据库报错时放行，让未认证请求覆盖
// 掉已有的管理员密码。
const errDataSourceUnavailable = "数据源暂时不可用，请稍后重试"

// validatePassword 返回空串表示通过，否则返回可直接展示给用户的中文原因。
func validatePassword(pw string) string {
	if utf8.RuneCountInString(pw) < minPasswordRunes {
		return fmt.Sprintf("密码长度至少 %d 位", minPasswordRunes)
	}
	if len(pw) > maxPasswordBytes {
		return fmt.Sprintf("密码长度不能超过 %d 字节", maxPasswordBytes)
	}
	return ""
}

// loadOrCreateJWTKey reads the 32-byte signing key from keyDir/jwt.key. keyDir is
// the project base dir (next to the executable), NOT the browsable workspace root
// (dataDir) — the signing key must never be listable/downloadable via the file
// manager. Legacy installs kept it at dataDir/jwt.key; if present there and not yet
// at the new location, it is migrated (key preserved, so sessions stay valid) and
// the old file removed so it disappears from the workspace. On first run a random
// key is generated and persisted.
func loadOrCreateJWTKey(keyDir, dataDir string) ([]byte, error) {
	path := filepath.Join(keyDir, jwtKeyFilename)
	// one-time migration out of the old in-workspace location.
	if legacy := filepath.Join(dataDir, jwtKeyFilename); legacy != path {
		if _, err := os.Stat(path); os.IsNotExist(err) {
			if data, rerr := os.ReadFile(legacy); rerr == nil {
				if werr := os.WriteFile(path, data, 0o600); werr == nil {
					_ = os.Remove(legacy)
					log.Printf("[auth] JWT key 已从 %s 迁移到 %s（移出可浏览工作区）", legacy, path)
				}
			}
		}
	}
	if data, err := os.ReadFile(path); err == nil && len(strings.TrimSpace(string(data))) >= 32 {
		return []byte(strings.TrimSpace(string(data))), nil
	}
	buf, err := generateJWTKey()
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, buf, 0600); err != nil {
		return nil, fmt.Errorf("write jwt key: %w", err)
	}
	log.Printf("[auth] 新 JWT key 已写入 %s", path)
	return buf, nil
}

// generateJWTKey produces a fresh 32-char random signing key.
func generateJWTKey() ([]byte, error) {
	buf := make([]byte, 32)
	for i := range buf {
		n, err := rand.Int(rand.Reader, big.NewInt(int64(len(keyChars))))
		if err != nil {
			return nil, fmt.Errorf("generate jwt key: %w", err)
		}
		buf[i] = keyChars[n.Int64()]
	}
	return buf, nil
}

// currentJWTKey snapshots the active signing key under the read lock; the key
// is swapped by rotateJWTKey after a password change.
func (s *Server) currentJWTKey() []byte {
	s.jwtKeyMu.RLock()
	defer s.jwtKeyMu.RUnlock()
	return s.jwtKey
}

// rotateJWTKey generates a fresh signing key, persists it to keyDir/jwt.key and
// swaps it in. Called right after a successful password change: JWTs are
// stateless (no jti / revocation list), so without rotation a leaked token
// would remain valid for up to jwtTTL regardless of the new password.
// Rotation revokes every previously issued token at once; the change-password
// response carries a fresh token so the current session stays logged in.
func (s *Server) rotateJWTKey() error {
	key, err := generateJWTKey()
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(s.keyDir, jwtKeyFilename), key, 0o600); err != nil {
		return fmt.Errorf("write jwt key: %w", err)
	}
	s.jwtKeyMu.Lock()
	s.jwtKey = key
	s.jwtKeyMu.Unlock()
	log.Printf("[auth] 密码已修改，JWT 签名密钥已轮换（此前签发的 token 全部失效）")
	return nil
}

// signJWT issues a 7-day HS256 token for user ARTEX.
func signJWT(key []byte) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.RegisteredClaims{
		Subject:   "ARTEX",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(jwtTTL)),
		IssuedAt:  jwt.NewNumericDate(time.Now()),
	}).SignedString(key)
}

// verifyJWT returns true when tokenStr is a valid, non-expired HS256 token.
func verifyJWT(tokenStr string, key []byte) bool {
	t, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method")
		}
		return key, nil
	})
	return err == nil && t.Valid
}

// extractToken reads the JWT from Authorization: Bearer header,
// artex_token cookie, or ?token= query param. The query param is an
// EventSource workaround (it cannot set request headers) and is accepted on
// the SSE stream endpoints only — anywhere else it would leak the JWT into
// access logs, proxy logs and Referer headers.
func extractToken(r *http.Request) string {
	if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	if c, err := r.Cookie("artex_token"); err == nil && c.Value != "" {
		return c.Value
	}
	if strings.HasSuffix(r.URL.Path, "/stream") {
		return r.URL.Query().Get("token")
	}
	return ""
}

// requireAuth wraps h with JWT validation.
// /api/auth/* and /api/health are exempt.
func (s *Server) requireAuth(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := r.URL.Path
		if strings.HasPrefix(p, "/api/auth/") || p == "/api/health" {
			h.ServeHTTP(w, r)
			return
		}
		tok := extractToken(r)
		if tok == "" {
			writeErr(w, 401, "未授权")
			return
		}
		if !verifyJWT(tok, s.currentJWTKey()) {
			writeErr(w, 401, "token 无效或已过期")
			return
		}
		h.ServeHTTP(w, r)
	})
}

// GET /api/auth/status — reports whether the admin password has been initialised.
// 读失败必须回 503 而不是 initialized:false：前端在 initialized:false 时会把用户
// 送到 /setup 去设置密码（login/page.tsx），把数据库故障包装成 200 等于把用户往
// 覆盖已有密码的路上推。
func (s *Server) authStatus(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	hash, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	writeJSON(w, 200, map[string]any{"initialized": hash != ""})
}

// POST /api/auth/init — sets the password for the first time; rejected if already set.
func (s *Server) authInit(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	existing, _, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if existing != "" {
		writeErr(w, 403, "密码已设置")
		return
	}
	var req struct {
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil || req.Password == "" {
		writeErr(w, 400, "密码不能为空")
		return
	}
	if msg := validatePassword(req.Password); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	// 用 INSERT ... ON CONFLICT DO NOTHING 而不是 upsert：上面那次 GetSetting 只是
	// 快速失败路径，真正"仅首次可设"的保证落在主键约束上。bcrypt 要跑几十毫秒，
	// 这期间别的请求完全可能先把密码设好，而读检查本身也可能因故障而失效。
	inserted, err := pg.InsertSettingIfAbsent(authPassKey, string(hash))
	if err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	if !inserted {
		writeErr(w, 403, "密码已设置")
		return
	}
	tok, err := signJWT(s.currentJWTKey())
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}

// POST /api/auth/change-password — changes the admin password. Requires a valid
// token (this route is under /api/auth/* which requireAuth exempts, so the token
// is validated here) AND the current password. On success the JWT signing key is
// rotated: every previously issued token (including any stolen one) becomes
// invalid immediately, and the response carries a fresh token so the current
// session stays logged in.
func (s *Server) authChangePassword(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	if !verifyJWT(extractToken(r), s.currentJWTKey()) {
		writeErr(w, 401, "未授权")
		return
	}
	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	if req.NewPassword == "" {
		writeErr(w, 400, "新密码不能为空")
		return
	}
	if msg := validatePassword(req.NewPassword); msg != "" {
		writeErr(w, 400, msg)
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "密码未初始化，请先设置密码")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.OldPassword)); err != nil {
		writeErr(w, 401, "当前密码错误")
		return
	}
	newHash, err := bcrypt.GenerateFromPassword([]byte(req.NewPassword), bcrypt.DefaultCost)
	if err != nil {
		writeErr(w, 500, "密码加密失败")
		return
	}
	if err := pg.SetSetting(authPassKey, string(newHash)); err != nil {
		writeErr(w, 500, "保存失败: "+err.Error())
		return
	}
	if err := s.rotateJWTKey(); err != nil {
		// 密码本身已改成功；密钥轮换失败只意味着旧 token 未被吊销——如实告知
		// 而不是假装成功。重启进程即可重新加载（未被覆盖的）旧密钥，无数据风险。
		writeErr(w, 500, "密码已修改，但 JWT 密钥轮换失败（旧 token 在重启前仍有效）: "+err.Error())
		return
	}
	tok, err := signJWT(s.currentJWTKey())
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	writeJSON(w, 200, map[string]any{"ok": true, "token": tok})
}

// ---- login rate limiting ----------------------------------------------------
//
// Per-IP failed-attempt backoff for /auth/login. In-memory and per-process by
// design (single-admin intranet tool; RemoteAddr is the real peer unless behind
// a reverse proxy). bcrypt's cost already throttles each individual attempt —
// this stops sustained brute force from the LAN instead. 5 consecutive failures
// lock the IP out with exponential backoff (30s → 15min); a success or an
// expired lockout resets the counter.

const (
	loginFailThreshold = 5
	loginFailBaseDelay = 30 * time.Second
	loginFailMaxDelay  = 15 * time.Minute
)

type loginFailEntry struct {
	count int
	until time.Time
}

var (
	loginFailMu sync.Mutex
	loginFails  = map[string]*loginFailEntry{}
)

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// loginLocked reports whether the IP is currently locked out. Expired entries
// are treated as a clean slate: the counter resets once the lockout window has
// fully passed without further failures.
func loginLocked(ip string) (bool, time.Duration) {
	loginFailMu.Lock()
	defer loginFailMu.Unlock()
	e, ok := loginFails[ip]
	if !ok {
		return false, 0
	}
	if remaining := time.Until(e.until); remaining > 0 {
		return true, remaining
	}
	delete(loginFails, ip)
	return false, 0
}

func recordLoginFailure(ip string) {
	loginFailMu.Lock()
	defer loginFailMu.Unlock()
	if len(loginFails) > 4096 { // defensive sweep; peers are few and real
		now := time.Now()
		for k, v := range loginFails {
			if now.After(v.until) {
				delete(loginFails, k)
			}
		}
	}
	e := loginFails[ip]
	if e == nil {
		e = &loginFailEntry{}
		loginFails[ip] = e
	}
	e.count++
	if e.count >= loginFailThreshold {
		d := loginFailBaseDelay << min(e.count-loginFailThreshold, 5)
		if d > loginFailMaxDelay || d <= 0 { // <=0 guards shift overflow
			d = loginFailMaxDelay
		}
		e.until = time.Now().Add(d)
	}
}

func clearLoginFailures(ip string) {
	loginFailMu.Lock()
	defer loginFailMu.Unlock()
	delete(loginFails, ip)
}

// POST /api/auth/login — validates username/password and returns a JWT.
func (s *Server) authLogin(w http.ResponseWriter, r *http.Request) {
	pg := s.pg(w)
	if pg == nil {
		return
	}
	ip := clientIP(r)
	if locked, wait := loginLocked(ip); locked {
		writeErr(w, 429, fmt.Sprintf("登录尝试过于频繁，请 %d 秒后再试", int(wait.Seconds())+1))
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := decode(r, &req); err != nil {
		writeErr(w, 400, "请求格式错误")
		return
	}
	fail := func() {
		recordLoginFailure(ip)
		writeErr(w, 401, "用户名或密码错误")
	}
	if req.Username != "ARTEX" {
		fail()
		return
	}
	hash, ok, err := pg.GetSetting(authPassKey)
	if err != nil {
		writeErr(w, 503, errDataSourceUnavailable)
		return
	}
	if !ok || hash == "" {
		writeErr(w, 403, "密码未初始化，请先设置密码")
		return
	}
	if err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(req.Password)); err != nil {
		fail()
		return
	}
	clearLoginFailures(ip)
	tok, err := signJWT(s.currentJWTKey())
	if err != nil {
		writeErr(w, 500, "token 生成失败")
		return
	}
	writeJSON(w, 200, map[string]any{"token": tok})
}
