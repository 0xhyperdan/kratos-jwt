package blademaster

import (
	"net/http"
	"os"

	"github.com/go-kratos/kratos/pkg/ecode"
	bm "github.com/go-kratos/kratos/pkg/net/http/blademaster"
	"github.com/go-kratos/kratos/pkg/net/metadata"
)

const (
	Pid     = "pid"     // 用户的父id业务场景：子账号
	IsAdmin = "isAdmin" // 是否是管理员
	Role    = "role"    // 用户身份
)

// User is used to mark path as access required.
// If `User-Agent` is exist in request form, it will using web access policy.
// Otherwise to web access policy.
// Mobile user-agent format "{platform};{device};{os_version};{app_version}"
// eg "User-Agent":"iOS;iPhone;12.6.1;1.0.0"
var (
	// _session       = "SESSION"
	_authorization = "Authorization"
	_envSecret     = "JWT_SECRET"
	_envExp        = "JWT_EXP_TIME"
	_bearer        = "Bearer "

	// os env no jwt_secret
	_osEnvError = ecode.Error(ecode.ServerErr, "环境变量缺少JWT_SECRET值")
	// _noTokenError 未传 token
	_noTokenError = ecode.Error(ecode.AccessDenied, "令牌未携带")
	// _failTokenError Token格式错误
	_failTokenError = ecode.Error(ecode.Unauthorized, "令牌格式错误")
	// _expiredTokenError token 过期
	_expiredTokenError = ecode.Error(ecode.Unauthorized, "令牌过期了，请重新登录")
	// _changeTokenError token 被窜改
	_changeTokenError = ecode.Error(ecode.AccessDenied, "令牌坏掉了")
	// 过期间隔 1176 hour 一个周
	//_envExp = time.Duration(1176 * (60 /*s*/ * 60 /*m*/))
	// test 1 min
	// _envExp = time.Duration(1 * 60)
)
var _filter = []string{
	"/ping",
	"/register",
	"/metrics",
	"/metadata",
	"/debug/pprof/profile",
}

// NoAuth not auth api
func NoAuth(filter []string) {
	if len(filter) == 0 {
		return
	}
	_filter = append(filter, _filter...)
}

// Auth token auth handler
func Auth() bm.HandlerFunc {
	return func(c *bm.Context) {
		req := c.Request
		noAuth := false
		for _, v := range _filter {
			if v == req.URL.Path {
				noAuth = true
			}
		}
		if noAuth || c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		key := req.Header.Get(_authorization)
		if key == "" {
			c.JSON(nil, _noTokenError)
			c.Abort()
			return
		}
		secret := os.Getenv(_envSecret)
		if secret == "" {
			c.JSON(nil, _osEnvError)
			c.Abort()
			return
		}
		// NOTE: 请求登录鉴权服务接口，拿到对应的用户id
		p, err := verifyToken(secret, key)
		if err != nil {
			c.JSON(nil, err)
			c.Abort()
			return
		}
		c.Set(metadata.Mid, p.MID)
		c.Set(Pid, p.PID)
		c.Set(Role, p.Role)
		c.Set(IsAdmin, p.IsAdmin)
		if md, ok := metadata.FromContext(c); ok {
			md[metadata.Mid] = p.MID
			md[Pid] = p.PID
			md[Role] = p.Role
			md[IsAdmin] = p.IsAdmin
		}
		c.Next()
	}
}
