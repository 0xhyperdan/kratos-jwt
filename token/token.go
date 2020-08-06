package token

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/go-kratos/kratos/pkg/log"
)

// JsonWebToken jwt
type JsonWebToken string

/*
iss：JsonWebToken token 的签发者
sub：主题
exp：JsonWebToken token 过期时间
aud：接收 JsonWebToken token 的一方
iat：JsonWebToken token 签发时间
nbf：JsonWebToken token 生效时间
jti：JsonWebToken token ID
*/
type payload struct {
	MID     int64         `json:"mid"`  // 用户ID
	PID     int64         `json:"pid"`  // 父id
	Role    int64         `json:"role"` // 账号角色
	Sub     string        `json:"sub"`
	Aud     string        `json:"aud"`
	Iss     string        `json:"iss"`
	Exp     time.Duration `json:"exp"`
	Nbf     time.Duration `json:"nbf"`
	Name    string        `json:"name"`
	IsAdmin bool          `json:"is_admin"` // 是否管理员
}

/**
token 的类型
token 所使用的加密算法
{
  "typ": "JsonWebToken",
  "alg": "HS256"
}
*/
type header struct {
	Typ string `json:"typ"`
	Alg string `json:"alg"`
}
type Token struct {
	Header  header
	Payload *payload
	Secret  string
}

/*
SIGNATURE
HMACSHA256(
  base64UrlEncode(header) + "." +
  base64UrlEncode(payload),
  secret
)
*/

// NewToken create new jwt token
func NewToken(name string, mid, pid, role int64, isAdmin bool) (jwt JsonWebToken, err error) {
	var (
		jwtSecret  string
		jwtExpTime string
		exp        int64
	)
	if jwtSecret = os.Getenv(_envSecret); jwtSecret == "" {
		log.Error("read os env error(%v)", _osEnvError)
		return "", _osEnvError
	}
	if jwtExpTime = os.Getenv(_envExp); jwtExpTime == "" {
		log.Error("read os env error(%v)", _osEnvError)
		return "", _osEnvError
	}
	if exp, err = strconv.ParseInt(jwtExpTime, 10, 64); err != nil {
		return "", err
	}
	// log.Info("jwtSecret=%s", jwtSecret)

	p := payload{}
	p.MID = mid
	p.PID = pid
	p.Name = name
	p.Role = role
	p.IsAdmin = isAdmin
	p.Iss = "iss"
	p.Sub = "sub"
	p.Aud = "aud"
	p.Nbf = now()
	p.Exp = p.Nbf + time.Duration(exp)

	head := newHeader()
	head64, payload64, secret265 := hs265(jwtSecret, head, p.string())
	return JsonWebToken(head64 + "." + payload64 + "." + secret265), nil
}

func hs265(secret string, head string, payload string) (hd64 string, pay64 string, sect string) {
	hm := hmac.New(sha256.New, []byte(secret))
	hd64 = base64.URLEncoding.EncodeToString([]byte(head))
	pay64 = base64.URLEncoding.EncodeToString([]byte(payload))
	hm.Write([]byte(hd64 + "." + pay64))
	sect = hex.EncodeToString(hm.Sum(nil))
	return
}

func (jwt JsonWebToken) String() string {
	return string(jwt)
}

func verifyToken(secret, t string) (_ *payload, err error) {
	var (
		jwt   = JsonWebToken(t)
		token *Token
	)
	if jwt == "null" || jwt == "" || !strings.Contains(t, _bearer) {
		return nil, _failTokenError
	}
	if token = jwt.parse(); token == nil {
		return nil, _failTokenError
	}
	if now() > token.Payload.Exp {
		return nil, _expiredTokenError
	}
	_, _, sec := hs265(secret, token.Header.string(), token.Payload.string())
	if token.Secret != sec {
		return nil, _changeTokenError
	}
	if token.Payload == nil {
		return nil, _failTokenError
	}
	return token.Payload, nil
}

// IsAdmin is admin
func (jwt JsonWebToken) IsAdmin() bool {
	return jwt.parse().Payload.IsAdmin
}

// GetMid get member id
func (jwt JsonWebToken) GetMid() int64 {
	return jwt.parse().Payload.MID
}

// GetPid get parent id
func (jwt JsonWebToken) GetPid() int64 {
	return jwt.parse().Payload.PID
}

// GetName get member name
func (jwt JsonWebToken) GetName() string {
	return jwt.parse().Payload.Name
}

func newHeader() string {
	header := header{Typ: "JsonWebToken", Alg: "HS256"}
	bytes, err := json.Marshal(header)
	if err != nil {
		log.Error("JsonWebToken token.header() error(%v)", err)
	}
	return string(bytes)
}

func now() time.Duration {
	return time.Duration(time.Now().Unix())
}

func (jwt JsonWebToken) parse() *Token {
	var (
		h         header
		p         payload
		secret265 string
	)
	token := strings.Replace(jwt.String(), _bearer, "", 1)
	sps := strings.Split(token, ".")
	if len(sps) != 3 {
		return nil
	}
	hb, err := base64.URLEncoding.DecodeString(sps[0])
	err = json.Unmarshal(hb, &h)
	pb, err := base64.URLEncoding.DecodeString(sps[1])
	err = json.Unmarshal(pb, &p)
	secret265 = sps[2]
	if err != nil {
		log.Error("JsonWebToken token.parse() error(%v)", err)
	}
	return &Token{Header: h, Payload: &p, Secret: secret265}
}

func (h header) string() string {
	bytes, err := json.Marshal(h)
	if err != nil {
		log.Error("JsonWebToken Header.string() error(%v)", err)
	}
	return string(bytes)
}

func (p payload) string() string {
	bytes, err := json.Marshal(p)
	if err != nil {
		log.Error("JsonWebToken p.string() error(%v)", err)
	}
	return string(bytes)
}
