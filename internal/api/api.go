package api

import (
	"fmt"
	"github.com/gorilla/mux"
	"github.com/samber/lo"
	"go.lumeweb.com/httputil"
	"go.lumeweb.com/portal-plugin-support/internal"
	"go.lumeweb.com/portal-plugin-support/internal/api/messages"
	pluginConfig "go.lumeweb.com/portal-plugin-support/internal/config"
	"go.lumeweb.com/portal/config"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/portal/middleware"
	"gopkg.in/oauth2.v3"
	"gopkg.in/oauth2.v3/manage"
	"gopkg.in/oauth2.v3/models"
	"gopkg.in/oauth2.v3/server"
	"gopkg.in/oauth2.v3/store"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

var _ core.API = (*API)(nil)

type API struct {
	ctx         core.Context
	config      config.Manager
	logger      *core.Logger
	oauthServer *server.Server
	user        core.UserService
}

func (a *API) Subdomain() string {
	dashApi := core.GetAPI("dashboard")

	if dashApi == nil {
		panic("dashboard service not found")
	}

	return dashApi.Subdomain()
}

func (a *API) Configure(router *mux.Router, accessSvc core.AccessService) error {
	pluginCfg := a.config.GetAPI(internal.PLUGIN_NAME).(*pluginConfig.APIConfig)

	// Middleware setup
	corsHandler := middleware.CorsMiddleware(nil)
	authMw := middleware.AuthMiddleware(middleware.AuthMiddlewareOptions{
		Context: a.ctx,
		Purpose: core.JWTPurposeLogin,
	})

	// OAuth manager setup
	manager := setupOAuthManager(pluginCfg)
	a.oauthServer = setupOAuthServer(manager)

	// Define routes
	routes := []struct {
		path    string
		method  string
		handler http.HandlerFunc
		mws     []mux.MiddlewareFunc
		access  string
	}{
		{"/api/account/support/oauth/authorize", "GET", a.authorize, []mux.MiddlewareFunc{authMw}, core.ACCESS_USER_ROLE},
		{"/api/account/support/oauth/token", "POST", a.token, nil, ""},
		{"/api/account/support/oauth/userinfo", "GET", a.userInfo, nil, ""},
		{"/api/account/support/oauth/userinfo", "POST", a.userInfo, nil, ""},
	}

	// Register routes
	router.Use(corsHandler)
	for _, route := range routes {
		r := router.HandleFunc(route.path, route.handler).Methods(route.method, "OPTIONS")
		r.Use(route.mws...)

		if err := accessSvc.RegisterRoute(a.Subdomain(), route.path, route.method, route.access); err != nil {
			return fmt.Errorf("failed to register route %s %s: %w", route.method, route.path, err)
		}
	}

	return nil
}

func (a *API) AuthTokenName() string {
	return core.AUTH_TOKEN_NAME
}

func (a *API) Config() config.APIConfig {
	return &pluginConfig.APIConfig{}
}

func (a *API) Name() string {
	return internal.PLUGIN_NAME
}

func (a *API) authorize(w http.ResponseWriter, r *http.Request) {
	err := a.oauthServer.HandleAuthorizeRequest(w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
	}
}

func (a *API) token(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	err := a.oauthServer.HandleTokenRequest(w, r)
	if err != nil {
		_ = ctx.Error(err, http.StatusBadRequest)
	}
}

func (a *API) userInfo(w http.ResponseWriter, r *http.Request) {
	ctx := httputil.Context(r, w)
	token, err := a.oauthServer.ValidationBearerToken(r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	userID, err := strconv.ParseUint(token.GetUserID(), 10, 64)
	if err != nil {
		_ = ctx.Error(err, http.StatusBadRequest)
		return
	}
	exists, userAcct, err := a.user.AccountExists(uint(userID))
	if err != nil {
		_ = ctx.Error(err, http.StatusInternalServerError)
		return
	}

	if !exists {
		acctErr := core.NewAccountError(core.ErrKeyUserNotFound, nil)
		_ = ctx.Error(acctErr, acctErr.HttpStatus())
		return
	}

	scopes := strings.Fields(token.GetScope())

	userInfo := messages.UserInfoResponse{
		Subject: token.GetUserID(),
	}

	if lo.Contains(scopes, "profile") {
		userInfo.Name = userAcct.FirstName + " " + userAcct.LastName
		userInfo.GivenName = userAcct.FirstName
		userInfo.FamilyName = userAcct.LastName
	}

	if lo.Contains(scopes, "email") {
		userInfo.Email = userAcct.Email
		userInfo.EmailVerified = userAcct.Verified
	}

	ctx.Request.Header.Set("Content-Type", "application/json")

	ctx.Encode(userInfo)
}

func NewAPI() (*API, []core.ContextBuilderOption, error) {
	api := &API{}

	return api, core.ContextOptions(
		core.ContextWithStartupFunc(func(ctx core.Context) error {
			api.ctx = ctx
			api.config = ctx.Config()
			api.logger = ctx.APILogger(api)
			api.user = core.GetService[core.UserService](ctx, core.USER_SERVICE)

			return nil
		}),
	), nil
}

func setupOAuthManager(pluginCfg *pluginConfig.APIConfig) *manage.Manager {
	manager := manage.NewDefaultManager()
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	clientStore := store.NewClientStore()
	parsedURL, err := url.Parse(pluginCfg.SupportPortalURL)
	if err != nil {
		log.Fatalf("Failed to parse SupportPortalURL: %v", err)
	}
	err = clientStore.Set(pluginCfg.ClientID, &models.Client{
		ID:     pluginCfg.ClientID,
		Secret: pluginCfg.ClientSecret,
		Domain: parsedURL.Host,
	})
	if err != nil {
		log.Fatalf("Failed to set client: %v", err)
	}

	manager.MapClientStorage(clientStore)
	return manager
}

func setupOAuthServer(manager oauth2.Manager) *server.Server {
	srv := server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(true)

	srv.SetUserAuthorizationHandler(func(w http.ResponseWriter, r *http.Request) (userID string, err error) {
		user, err := middleware.GetUserFromContext(r.Context())
		if err != nil {
			return "", err
		}
		return strconv.FormatInt(int64(user), 10), nil
	})

	srv.SetClientScopeHandler(func(_, scope string) (allowed bool, err error) {
		allowedScopes := []string{"openid", "profile", "email"}
		for _, s := range strings.Fields(scope) {
			if !lo.Contains(allowedScopes, s) {
				return false, nil
			}
		}
		return true, nil
	})

	return srv
}
