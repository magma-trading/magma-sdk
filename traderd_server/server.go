package traderd_server

import (
  "crypto/ed25519"
  "encoding/base64"
  "context"
  "crypto/rand"
  "encoding/json"
  "errors"
  "fmt"
  "io"
  "log"
  "net"
  "net/http"
  "os"
  "strings"
  "time"
  "crypto/sha512"
  "encoding/hex"

  bbolt "go.etcd.io/bbolt"
  "golang.org/x/term"

  "crypto/aes"
  "crypto/cipher"
  "crypto/hmac"
  "crypto/sha256"
)

var hashpwdMem string

var (
  SignPriv ed25519.PrivateKey
  SignPub  ed25519.PublicKey
)

type Req struct {
  Symbol string `json:"symbol"`
}

type Res struct {
  OK  bool   `json:"ok"`
  Msg string `json:"msg"`
  ID  string `json:"id,omitempty"`
}

const (
  maxBodyBytes    = 4 << 10 // 4KB
  ReadTimeout     = 5 * time.Second
  WriteTimeout    = 5 * time.Second
  IdleTimeout     = 30 * time.Second
  ShutdownTimeout = 5 * time.Second
)

type HashpwdResp struct {
  Hashpwd string `json:"hashpwd"`
}

func HashpwdHandler(w http.ResponseWriter, r *http.Request) {
  reqID := RequestIDFromContext(r.Context())
  if reqID == "no-id" {
    reqID = newReqID()
  }
  if r.Method != http.MethodGet {
    WriteSignedJSON(w, http.StatusMethodNotAllowed, reqID, map[string]any{
      "ok": false, "msg": "method not allowed", "id": reqID,
    })
    return
  }
  if hashpwdMem == "" {
    WriteSignedJSON(w, http.StatusNotFound, reqID, map[string]any{
      "ok": false, "msg": "hashpwd not set", "id": reqID,
    })
    return
  }
  WriteSignedJSON(w, http.StatusOK, reqID, HashpwdResp{Hashpwd: hashpwdMem})
}


func HealthHandler(w http.ResponseWriter, r *http.Request) {
  if r.Method != http.MethodGet {
    http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
    return
  }
  w.Header().Set("Content-Type", "text/plain; charset=utf-8")
  _, _ = w.Write([]byte("ok\n"))
}

func PlaceHandler(w http.ResponseWriter, r *http.Request) {

  reqID := RequestIDFromContext(r.Context())

  if r.Method != http.MethodPost {
    // writeJSON(w, http.StatusMethodNotAllowed, Res{OK: false, Msg: "method not allowed", ID: reqID})
    WriteSignedJSON(w, http.StatusMethodNotAllowed, reqID,
      Res{OK: false, Msg: "method not allowed", ID: reqID},
    )
    return
  }

  ct := r.Header.Get("Content-Type")
  if ct != "" && !strings.HasPrefix(ct, "application/json") {
    // writeJSON(w, http.StatusUnsupportedMediaType, Res{OK: false, Msg: "Content-Type must be application/json", ID: reqID})
    WriteSignedJSON(w, http.StatusUnsupportedMediaType, reqID,
      Res{OK: false, Msg: "Content-Type must be application/json", ID: reqID},
    )
    return
  }

  r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
  defer r.Body.Close()

  raw, err := io.ReadAll(r.Body)
  if err != nil {
    // writeJSON(w, http.StatusBadRequest, Res{OK: false, Msg: "failed to read body", ID: reqID})
    WriteSignedJSON(w, http.StatusBadRequest, reqID,
      Res{OK: false, Msg: "failed to read body", ID: reqID},
    )
    log.Printf("id=%s /place read body error: %v", reqID, err)
    return
  }

  preview := string(raw)
  if len(preview) > 512 {
    preview = preview[:512] + "...(truncated)"
  }
  log.Printf("id=%s /place received raw_json_len=%d raw_json=%q", reqID, len(raw), preview)

  var req Req
  dec := json.NewDecoder(strings.NewReader(string(raw)))
  dec.DisallowUnknownFields()
  if err := dec.Decode(&req); err != nil {
    // writeJSON(w, http.StatusBadRequest, Res{OK: false, Msg: "invalid JSON: " + err.Error(), ID: reqID})
    WriteSignedJSON(w, http.StatusBadRequest, reqID,
      Res{OK: false, Msg: "invalid JSON: " + err.Error(), ID: reqID},
    )

    log.Printf("id=%s /place decode error: %v", reqID, err)
    return
  }

  req.Symbol = strings.TrimSpace(req.Symbol)
  if req.Symbol == "" {
    // writeJSON(w, http.StatusBadRequest, Res{OK: false, Msg: "symbol is required", ID: reqID})
    WriteSignedJSON(w, http.StatusBadRequest, reqID,
      Res{OK: false, Msg: "symbol is required", ID: reqID},
    )
    log.Printf("id=%s /place invalid: empty symbol", reqID)
    return
  }

  log.Printf("id=%s /place parsed symbol=%q", reqID, req.Symbol)
  // writeJSON(w, http.StatusOK, Res{OK: true, Msg: "ok symbol=" + req.Symbol, ID: reqID})
  WriteSignedJSON(w, http.StatusOK, reqID, Res{OK: true, Msg: "ok symbol=" + req.Symbol, ID: reqID})

}

func WriteSignedJSON(w http.ResponseWriter, status int, reqID string, v any) {

  body, err := json.Marshal(v)
  if err != nil {
    http.Error(w, "internal error", http.StatusInternalServerError)
    return
  }

  // If you want a trailing newline for readability, add it to BOTH:
  // - what you send
  // - what you sign
  payload := append(body, '\n')

  msg := append([]byte(reqID+"\n"), payload...)
  sig := ed25519.Sign(SignPriv, msg)

  w.Header().Set("Content-Type", "application/json; charset=utf-8")
  w.Header().Set("X-Req-Id", reqID)
  w.Header().Set("X-Signature", base64.StdEncoding.EncodeToString(sig))
  w.WriteHeader(status)
  _, _ = w.Write(payload)
}

func LoggingMiddleware(next http.Handler) http.Handler {
  return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    id := newReqID()
    ctx := context.WithValue(r.Context(), ctxKeyReqID{}, id)

    start := time.Now()
    next.ServeHTTP(w, r.WithContext(ctx))
    d := time.Since(start)

    ra := r.RemoteAddr
    if ra == "" {
      ra = "unix"
    }
    log.Printf("id=%s method=%s path=%s remote=%s dur=%s", id, r.Method, r.URL.Path, ra, d)
  })
}

type ctxKeyReqID struct{}

func RequestIDFromContext(ctx context.Context) string {
  v := ctx.Value(ctxKeyReqID{})
  if s, ok := v.(string); ok && s != "" {
    return s
  }
  return "no-id"
}

func newReqID() string {
  var b [12]byte
  _, _ = rand.Read(b[:])
  return hex.EncodeToString(b[:])
}

/* =========================
   Allowlist file + outbound
   ========================= */

func LoadAllowlistFile(path string) ([]string, error) {

  b, err := os.ReadFile(path)
  if err != nil {
    return nil, fmt.Errorf("read allowlist file: %w", err)
  }

  seen := map[string]struct{}{}
  out := make([]string, 0, 64)

  lines := strings.Split(string(b), "\n")
  for i, line := range lines {
    orig := line
    line = strings.TrimSpace(line)
    if line == "" || strings.HasPrefix(line, "#") {
      continue
    }
    // inline comment
    if idx := strings.Index(line, "#"); idx >= 0 {
      line = strings.TrimSpace(line[:idx])
      if line == "" {
        continue
      }
    }

    // normalize
    d := strings.ToLower(line)
    d = strings.TrimSuffix(d, ".")
    if strings.ContainsAny(d, " \t\r") {
      return nil, fmt.Errorf("allowlist invalid at line %d: %q", i+1, orig)
    }

    if _, ok := seen[d]; ok {
      continue
    }
    seen[d] = struct{}{}
    out = append(out, d)
  }

  return out, nil
}

func domainAllowed(host string, allow []string) bool {
  h := strings.ToLower(strings.TrimSpace(host))
  h = strings.TrimSuffix(h, ".")
  if h == "" {
    return false
  }
  // deny IP literals (domain allowlist only)
  if net.ParseIP(h) != nil {
    return false
  }

  for _, a := range allow {
    if a == "" {
      continue
    }
    if strings.HasPrefix(a, ".") {
      suffix := strings.TrimPrefix(a, ".")
      if h == suffix || strings.HasSuffix(h, "."+suffix) {
        return true
      }
    } else {
      if h == a {
        return true
      }
    }
  }
  return false
}

type allowlistRoundTripper struct {
  base    http.RoundTripper
  allowed []string
}

func (rt *allowlistRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
  host := req.URL.Hostname()
  if !domainAllowed(host, rt.allowed) {
    return nil, fmt.Errorf("outbound blocked: host %q not in allowlist", host)
  }
  return rt.base.RoundTrip(req)
}

func NewAllowlistedHTTPClient(allow []string) *http.Client {
  dialer := &net.Dialer{
    Timeout:   5 * time.Second,
    KeepAlive: 30 * time.Second,
  }

  t := &http.Transport{
    Proxy: nil, // avoid proxy env bypass
    DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
      // address: "host:port"
      host := address
      if strings.Contains(address, ":") {
        host, _, _ = strings.Cut(address, ":")
      }
      if !domainAllowed(host, allow) {
        return nil, fmt.Errorf("dial blocked: host %q not in allowlist", host)
      }
      return dialer.DialContext(ctx, network, address)
    },
    ForceAttemptHTTP2:     true,
    MaxIdleConns:          32,
    IdleConnTimeout:       30 * time.Second,
    TLSHandshakeTimeout:   5 * time.Second,
    ExpectContinueTimeout: 1 * time.Second,
  }

  return &http.Client{
    Transport: &allowlistRoundTripper{base: t, allowed: allow},
    Timeout:   15 * time.Second,
  }
}

// password - begin

func PromptAndStorePasswordHash2Pwd(dbPath string) (error) {

  fmt.Println("IMPORTANT: Your password is NOT recoverable.")
  fmt.Println("If you lose it, it will be IMPOSSIBLE to recover or restore any data from the local database.")
  fmt.Println("Please store it securely (e.g., a password manager).")
  fmt.Println()

  pwd, err := promptPasswordTwice()
  if err != nil {
    return err
  }

  if err := validatePassword(pwd); err != nil {
    return err
  }

  // hash2pwd = sha512(sha512(password))
  sum1 := sha512.Sum512([]byte(pwd))
  sum2 := sha512.Sum512(sum1[:])
  hash2pwd := hex.EncodeToString(sum2[:])

  // Store in BoltDB
  db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: 1 * time.Second})
  if err != nil {
    return err
  }
  defer db.Close()

  if err := db.Update(func(tx *bbolt.Tx) error {
    b, err := tx.CreateBucketIfNotExists([]byte("auth"))
    if err != nil {
      return err
    }
    return b.Put([]byte("hash2pwd"), []byte(hash2pwd))
  }); err != nil {
    return err
  }

  fmt.Println("hash2pwd:", hash2pwd)
  hashpwdMem = hash2pwd
  return nil
}

func promptPasswordTwice() (string, error) {
  for {
    fmt.Print("Enter password: ")
    p1, err := readHidden()
    if err != nil {
      return "", err
    }

    fmt.Print("Re-enter password: ")
    p2, err := readHidden()
    if err != nil {
      return "", err
    }

    if p1 != p2 {
      fmt.Println("Passwords do not match. Try again.")
      continue
    }
    return p1, nil
  }
}

func readHidden() (string, error) {
  // Reads from terminal, masked
  b, err := term.ReadPassword(int(os.Stdin.Fd()))
  fmt.Println()
  if err != nil {
    return "", err
  }
  return string(b), nil
}

func validatePassword(p string) error {

  if len(p) < 3 { //16 {
    return errors.New("password must be at least 16 characters")
  }

  hasLetter := false
  hasDigit := false
  hasSpecial := false

  for _, r := range p {
    switch {
    case r >= 'a' && r <= 'z':
      hasLetter = true
    case r >= 'A' && r <= 'Z':
      hasLetter = true
    case r >= '0' && r <= '9':
      hasDigit = true
    case r == '@' || r == '#' || r == '$' || r == '%':
      hasSpecial = true
    default:
      return fmt.Errorf("invalid character %q (allowed: A-Z a-z 0-9 @ # $ %%)", r)
    }
  }

  if !hasLetter {
    return errors.New("password must include at least 1 letter")
  }
  if !hasDigit {
    return errors.New("password must include at least 1 digit")
  }
  if !hasSpecial {
    return errors.New("password must include at least 1 special character from @#$%")
  }
  return nil
}

// password - end

// banner - begin

func PrintStartupBanner(appName, subtitle, version string) {
  const totalWidth = 49         // length of the top/bottom line
  const innerLineWidth = 45      // content width inside "║ <content> ║"
  const borderWidth = totalWidth - 2 // "═" count

  leftPad := 0
  if w, ok := termWidth(); ok && w > totalWidth {
    leftPad = (w - totalWidth) / 2
  }

  prefix := strings.Repeat(" ", leftPad)

  top := "╔" + strings.Repeat("═", borderWidth) + "╗"
  bot := "╚" + strings.Repeat("═", borderWidth) + "╝"

  row := func(s string) string {
    // truncate if too long
    if len(s) > innerLineWidth {
      if innerLineWidth > 3 {
        s = s[:innerLineWidth-3] + "..."
      } else {
        s = s[:innerLineWidth]
      }
    }
    return "║ " + s + strings.Repeat(" ", innerLineWidth-len(s)) + " ║"
  }
  fmt.Println(prefix + top)
  fmt.Println(prefix + row(appName))
  fmt.Println(prefix + row(subtitle))
  fmt.Println(prefix + row("Version: "+version))
  fmt.Println(prefix + row("Started: "+time.Now().Format("2006-01-02 15:04:05")))
  fmt.Println(prefix + bot)
}

func termWidth() (int, bool) {
  fd := int(os.Stdout.Fd())
  if !term.IsTerminal(fd) {
    return 0, false
  }
  w, _, err := term.GetSize(fd)
  if err != nil || w <= 0 {
    return 0, false
  }
  return w, true
}

// banner - end

// db - begin

var ErrNotFound = errors.New("record not found")

const (
  bucketRecords = "records"   // field0 -> encrypted blob
  bucketIdxF6   = "idx_field6" // HMAC(field6) -> field0
)

/*
api id			field0 string
exchange:		field1 string
updated:		field2 time
api key:		field3 string
api secret:		field4 string
passphrase:		field5 string
label:			field6 string
testnet:		bool
api enabled:		bool
*/

type Record struct {
  Field0 string
  Field1 string
  Field2 time.Time
  Field3 string
  Field4 string
  Field5 string
  Field6 string
  Field7 bool
  Field8 bool
}

type encPayload struct {
  Field1 string `json:"field1"`
  Field2 int64  `json:"field2_unix_nano"`
  Field3 string `json:"field3"`
  Field4 string `json:"field4"`
  Field5 string `json:"field5"`
  Field6 string `json:"field6"`
  Field7 bool   `json:"field7"`
  Field8 bool   `json:"field8"`
}

/* =========================
   HTTP handlers
   ========================= */

type WriteRecordReq struct {
  Hashpwd string `json:"hashpwd"`
  Record  Record `json:"record"`
}

type WriteRecordRes struct {
  OK  bool   `json:"ok"`
  Msg string `json:"msg"`
  ID  string `json:"id,omitempty"`
}

// PutRecord stores:
// - key:   field0 (plaintext)
// - value: version(1) || nonce(12) || gcm(ciphertext), where plaintext is JSON of fields1..8
// Also updates secondary index: HMAC(key, field6) -> field0
func PutRecord(db *bbolt.DB, hashpwd string, rec Record) error {

  if rec.Field0 == "" {
    return fmt.Errorf("field0 is required")
  }
  key32, err := deriveKey32(hashpwd)
  if err != nil {
    return err
  }
  gcm, err := newGCM(key32)
  if err != nil {
    return err
  }

  p := encPayload{
    Field1: rec.Field1,
    Field2: rec.Field2.UnixNano(),
    Field3: rec.Field3,
    Field4: rec.Field4,
    Field5: rec.Field5,
    Field6: rec.Field6,
    Field7: rec.Field7,
    Field8: rec.Field8,
  }

  plain, err := json.Marshal(p)
  if err != nil {
    return err
  }

  nonce := make([]byte, 12)
  if _, err := rand.Read(nonce); err != nil {
    return err
  }

  // Bind ciphertext to field0 to prevent swapping records between keys.
  aad := []byte(rec.Field0)
  ct := gcm.Seal(nil, nonce, plain, aad)

  // value format: [1-byte version][12-byte nonce][ciphertext]
  val := make([]byte, 0, 1+len(nonce)+len(ct))
  val = append(val, 1) // version
  val = append(val, nonce...)
  val = append(val, ct...)

  return db.Update(func(tx *bbolt.Tx) error {
		br, err := tx.CreateBucketIfNotExists([]byte(bucketRecords))
		if err != nil {
			return err
		}
		bi, err := tx.CreateBucketIfNotExists([]byte(bucketIdxF6))
		if err != nil {
			return err
		}

		k0 := []byte(rec.Field0)

		// If record exists, remove old field6 index (if decrypt succeeds)
		if old := br.Get(k0); old != nil {
			if oldP, derr := decryptPayload(gcm, rec.Field0, old); derr == nil {
				oldIdxKey := idxKeyForField6(key32, oldP.Field6)
				_ = bi.Delete(oldIdxKey)
			}
		}

		// Write record
		if err := br.Put(k0, val); err != nil {
			return err
		}

		// Write/Update index for field6 (HMAC so field6 isn't leaked in DB keys)
		idxKey := idxKeyForField6(key32, rec.Field6)
		return bi.Put(idxKey, k0)
  })
}

// GetRecordByField0 reads record by plaintext key field0.
// Requires hashpwd to decrypt fields1..8.
func GetRecordByField0(db *bbolt.DB, hashpwd string, field0 string) (Record, error) {
	if field0 == "" {
		return Record{}, fmt.Errorf("field0 is required")
	}
	key32, err := deriveKey32(hashpwd)
	if err != nil {
		return Record{}, err
	}
	gcm, err := newGCM(key32)
	if err != nil {
		return Record{}, err
	}

	var out Record
	err = db.View(func(tx *bbolt.Tx) error {
		br := tx.Bucket([]byte(bucketRecords))
		if br == nil {
			return ErrNotFound
		}
		val := br.Get([]byte(field0))
		if val == nil {
			return ErrNotFound
		}

		p, err := decryptPayload(gcm, field0, val)
		if err != nil {
			return err
		}

		out = Record{
			Field0: field0,
			Field1: p.Field1,
			Field2: time.Unix(0, p.Field2),
			Field3: p.Field3,
			Field4: p.Field4,
			Field5: p.Field5,
			Field6: p.Field6,
			Field7: p.Field7,
			Field8: p.Field8,
		}
		return nil
	})
	return out, err
}

/* ----------------- internals ----------------- */

func deriveKey32(hashpwd string) ([]byte, error) {
	s := hashpwd
	if s == "" {
		return nil, fmt.Errorf("hashpwd is empty")
	}

	// Accept hex-encoded sha512 (128 hex chars). If not hex, use raw bytes.
	var material []byte
	if b, err := hex.DecodeString(s); err == nil && len(b) > 0 {
		material = b
	} else {
		material = []byte(s)
	}

	sum := sha256.Sum256(material) // -> 32 bytes AES-256 key
	key32 := make([]byte, 32)
	copy(key32, sum[:])
	return key32, nil
}

func decryptPayload(gcm cipher.AEAD, field0 string, val []byte) (encPayload, error) {
	if len(val) < 1+12 {
		return encPayload{}, fmt.Errorf("ciphertext too short")
	}
	if val[0] != 1 {
		return encPayload{}, fmt.Errorf("unsupported version: %d", val[0])
	}
	nonce := val[1 : 1+12]
	ct := val[1+12:]

	plain, err := gcm.Open(nil, nonce, ct, []byte(field0))
	if err != nil {
		return encPayload{}, err
	}
	var p encPayload
	if err := json.Unmarshal(plain, &p); err != nil {
		return encPayload{}, err
	}
	return p, nil
}

func idxKeyForField6(key32 []byte, field6 string) []byte {
  // HMAC-SHA256(key32, field6) -> 32 bytes
  m := hmac.New(sha256.New, key32)
  m.Write([]byte(field6))
  return m.Sum(nil)
}

//---

type ListIDsRes struct {
  OK  bool     `json:"ok"`
  Msg string   `json:"msg"`
  ID  string   `json:"id,omitempty"`
  IDs []string `json:"ids,omitempty"`
}

func ListRecordIDsHandler(db *bbolt.DB) http.HandlerFunc {

  return func(w http.ResponseWriter, r *http.Request) {
    reqID := RequestIDFromContext(r.Context())
    if reqID == "no-id" { reqID = newReqID() }

    if r.Method != http.MethodGet {
      WriteSignedJSON(w, http.StatusMethodNotAllowed, reqID,
        ListIDsRes{OK: false, Msg: "method not allowed", ID: reqID})
      return
    }

    var ids []string
    err := db.View(func(tx *bbolt.Tx) error {
      b := tx.Bucket([]byte(bucketRecords)) // the bucket where field0->ciphertext lives
      if b == nil {
        return nil
      }
      return b.ForEach(func(k, _ []byte) error {
        ids = append(ids, string(k))
        return nil
      })
    })
    if err != nil {
      WriteSignedJSON(w, http.StatusInternalServerError, reqID,
        ListIDsRes{OK: false, Msg: "db error: " + err.Error(), ID: reqID})
      return
    }

    WriteSignedJSON(w, http.StatusOK, reqID,
      ListIDsRes{OK: true, Msg: "ok", ID: reqID, IDs: ids})
    }
}

func StoreWriteHandler(db *bbolt.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := RequestIDFromContext(r.Context())
		if reqID == "no-id" {
			reqID = newReqID()
		}

		if r.Method != http.MethodPost {
			WriteSignedJSON(w, http.StatusMethodNotAllowed, reqID, WriteRecordRes{OK: false, Msg: "method not allowed", ID: reqID})
			return
		}

		ct := r.Header.Get("Content-Type")
		if ct != "" && !strings.HasPrefix(ct, "application/json") {
			WriteSignedJSON(w, http.StatusUnsupportedMediaType, reqID, WriteRecordRes{OK: false, Msg: "Content-Type must be application/json", ID: reqID})
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
		defer r.Body.Close()

		raw, err := io.ReadAll(r.Body)
		if err != nil {
			WriteSignedJSON(w, http.StatusBadRequest, reqID, WriteRecordRes{OK: false, Msg: "failed to read body", ID: reqID})
			return
		}

		var req WriteRecordReq
		dec := json.NewDecoder(strings.NewReader(string(raw)))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&req); err != nil {
			WriteSignedJSON(w, http.StatusBadRequest, reqID, WriteRecordRes{OK: false, Msg: "invalid JSON: " + err.Error(), ID: reqID})
			return
		}

		req.Record.Field0 = strings.TrimSpace(req.Record.Field0)
		req.Record.Field6 = strings.TrimSpace(req.Record.Field6)
		if strings.TrimSpace(req.Hashpwd) == "" {
			WriteSignedJSON(w, http.StatusBadRequest, reqID, WriteRecordRes{OK: false, Msg: "hashpwd is required", ID: reqID})
			return
		}
		if req.Record.Field0 == "" {
			WriteSignedJSON(w, http.StatusBadRequest, reqID, WriteRecordRes{OK: false, Msg: "field0 is required", ID: reqID})
			return
		}

		// (Optional) don’t allow IP literals in field0 if you later use it as hostname, etc.
		if net.ParseIP(req.Record.Field0) != nil {
			// not necessary, just an example of strictness
		}

		if err := PutRecord(db, req.Hashpwd, req.Record); err != nil {
			WriteSignedJSON(w, http.StatusInternalServerError, reqID, WriteRecordRes{OK: false, Msg: "store error: " + err.Error(), ID: reqID})
			return
		}

		// Don’t print hashpwd in logs; it’s effectively a key.
		WriteSignedJSON(w, http.StatusOK, reqID, WriteRecordRes{OK: true, Msg: "stored", ID: reqID})
	}
}

type ReadRecordReq struct {
  Hashpwd string `json:"hashpwd"`
  Field0  string `json:"field0"`
}

type ReadRecordRes struct {
  OK     bool    `json:"ok"`
  Msg    string  `json:"msg"`
  ID     string  `json:"id,omitempty"`
  Record *Record `json:"record,omitempty"`
}

func StoreReadHandler(db *bbolt.DB) http.HandlerFunc {
  return func(w http.ResponseWriter, r *http.Request) {
    reqID := RequestIDFromContext(r.Context())
    if reqID == "no-id" {
      reqID = newReqID()
    }

    if r.Method != http.MethodPost {
      WriteSignedJSON(w, http.StatusMethodNotAllowed, reqID, ReadRecordRes{OK: false, Msg: "method not allowed", ID: reqID})
      return
    }

    ct := r.Header.Get("Content-Type")
    if ct != "" && !strings.HasPrefix(ct, "application/json") {
      WriteSignedJSON(w, http.StatusUnsupportedMediaType, reqID, ReadRecordRes{OK: false, Msg: "Content-Type must be application/json", ID: reqID})
      return
    }

    r.Body = http.MaxBytesReader(w, r.Body, maxBodyBytes)
    defer r.Body.Close()

    raw, err := io.ReadAll(r.Body)
    if err != nil {
      WriteSignedJSON(w, http.StatusBadRequest, reqID, ReadRecordRes{OK: false, Msg: "failed to read body", ID: reqID})
      return
    }

    var req ReadRecordReq
    dec := json.NewDecoder(strings.NewReader(string(raw)))
    dec.DisallowUnknownFields()
    if err := dec.Decode(&req); err != nil {
      WriteSignedJSON(w, http.StatusBadRequest, reqID, ReadRecordRes{OK: false, Msg: "invalid JSON: " + err.Error(), ID: reqID})
      return
    }

    req.Field0 = strings.TrimSpace(req.Field0)
    if strings.TrimSpace(req.Hashpwd) == "" {
      WriteSignedJSON(w, http.StatusBadRequest, reqID, ReadRecordRes{OK: false, Msg: "hashpwd is required", ID: reqID})
      return
    }
    if req.Field0 == "" {
      WriteSignedJSON(w, http.StatusBadRequest, reqID, ReadRecordRes{OK: false, Msg: "field0 is required", ID: reqID})
      return
    }

    rec, err := GetRecordByField0(db, req.Hashpwd, req.Field0)
    if err != nil {
      if errors.Is(err, ErrNotFound) {
        WriteSignedJSON(w, http.StatusNotFound, reqID, ReadRecordRes{OK: false, Msg: "not found", ID: reqID})
        return
      }
      WriteSignedJSON(w, http.StatusUnauthorized, reqID, ReadRecordRes{OK: false, Msg: "decrypt/store error: " + err.Error(), ID: reqID})
      return
    }
    WriteSignedJSON(w, http.StatusOK, reqID, ReadRecordRes{OK: true, Msg: "ok", ID: reqID, Record: &rec})
  }
}

func newGCM(key32 []byte) (cipher.AEAD, error) {
  if len(key32) != 32 {
    return nil, fmt.Errorf("bad key length: %d", len(key32))
  }
  block, err := aes.NewCipher(key32)
  if err != nil {
    return nil, err
  }
  return cipher.NewGCM(block)
}

// db - end

/*
package main

import (
	"fmt"
	"time"

	bbolt "go.etcd.io/bbolt"

	"yourmodule/store"
)

func main() {
	db, err := bbolt.Open("./data.db", 0600, nil)
	if err != nil { panic(err) }
	defer db.Close()

	hashpwd := "sha512sha512-of-password-here" // e.g. hex string

	rec := store.Record{
		Field0: "id_123",
		Field1: "secret1",
		Field2: time.Now(),
		Field3: "secret3",
		Field4: "secret4",
		Field5: "secret5",
		Field6: "alt_key_ABC",
		Field7: true,
		Field8: false,
	}

	if err := store.PutRecord(db, hashpwd, rec); err != nil {
		panic(err)
	}

	got, err := store.GetRecordByField0(db, hashpwd, "id_123")
	if err != nil {
		panic(err)
	}
	fmt.Printf("%+v\n", got)
}

*/
