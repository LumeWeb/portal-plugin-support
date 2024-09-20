package api

import (
	"github.com/gorilla/mux"
	"github.com/rs/cors"
	"github.com/samber/lo"
	"go.lumeweb.com/httputil"
	"go.lumeweb.com/portal-plugin-support/internal"
	"go.lumeweb.com/portal-plugin-support/internal/api/messages"
	pluginConfig "go.lumeweb.com/portal-plugin-support/internal/config"
	"go.lumeweb.com/portal/config"
	"go.lumeweb.com/portal/core"
	"go.lumeweb.com/portal/middleware"
	"gopkg.in/oauth2.v3/manage"
	"gopkg.in/oauth2.v3/models"
	"gopkg.in/oauth2.v3/server"
	"gopkg.in/oauth2.v3/store"
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

func (a *API) Configure(router *mux.Router) error {
	pluginCfg := a.config.GetAPI(internal.PLUGIN_NAME).(*pluginConfig.APIConfig)
	corsOpts := cors.Options{
		AllowOriginFunc: func(origin string) bool {
			return true
		},
		AllowedMethods:   []string{"GET", "POST", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Authorization", "Content-Type"},
		AllowCredentials: true,
	}

	corsHandler := cors.New(corsOpts)
	authMw := middleware.AuthMiddleware(middleware.AuthMiddlewareOptions{
		Context: a.ctx,
		Purpose: core.JWTPurposeLogin,
	})

	manager := manage.NewDefaultManager()
	manager.MustTokenStorage(store.NewMemoryTokenStore())

	clientStore := store.NewClientStore()
	parsedURL, err := url.Parse(pluginCfg.SupportPortalURL)
	if err != nil {
		return err
	}
	err = clientStore.Set(pluginCfg.ClientID, &models.Client{
		ID:     pluginCfg.ClientID,
		Secret: pluginCfg.ClientSecret,
		Domain: parsedURL.Host,
	})
	if err != nil {
		return err
	}

	manager.MapClientStorage(clientStore)

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
		for _, scope := range strings.Fields(scope) {
			if !lo.Contains(allowedScopes, scope) {
				return false, nil
			}
		}

		return true, nil
	})

	a.oauthServer = srv

	router.Use(corsHandler.Handler)

	router.HandleFunc("/api/account/support/oauth/authorize", a.authorize).Methods("GET", "OPTIONS").Use(authMw)
	router.HandleFunc("/api/account/support/oauth/token", a.token).Methods("POST", "OPTIONS")
	router.HandleFunc("/api/account/support/oauth/userinfo", a.userInfo).Methods("GET", "POST", "OPTIONS")

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
