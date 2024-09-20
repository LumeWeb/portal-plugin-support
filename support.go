package support

import (
	"go.lumeweb.com/portal-plugin-support/internal"
	"go.lumeweb.com/portal-plugin-support/internal/api"
	pluginConfig "go.lumeweb.com/portal-plugin-support/internal/config"
	"go.lumeweb.com/portal/core"
)

func init() {
	core.RegisterPlugin(core.PluginInfo{
		ID: internal.PLUGIN_NAME,
		Meta: func(ctx core.Context, builder core.PortalMetaBuilder) error {
			pluginCfg := ctx.Config().GetPlugin(internal.PLUGIN_NAME).API.(*pluginConfig.APIConfig)
			builder.AddFeatureFlag("support", true)
			builder.AddPluginMeta(internal.PLUGIN_NAME, "support_portal", pluginCfg.SupportPortalURL)
			builder.AddPluginMeta(internal.PLUGIN_NAME, "mailbox_id", pluginCfg.MailboxID)

			return nil
		},
		API: func() (core.API, []core.ContextBuilderOption, error) {
			return api.NewAPI()
		},
		Depends: []string{"dashboard"},
	})
}
