package detecode

import (
	"github.com/zricethezav/gitleaks/v8/cmd/generate/config/rules"
	"github.com/zricethezav/gitleaks/v8/config"
	"github.com/zricethezav/gitleaks/v8/detect"
	"strings"
)

var secretRules []*config.Rule

func addRule(rule *config.Rule) {
	secretRules = append(secretRules, rule)
}

func newSubDetector(rule *config.Rule) *detect.Detector {
	// normalize keywords like in the config package
	for i := range rule.Keywords {
		rule.Keywords[i] = strings.ToLower(rule.Keywords[i])
	}

	return detect.NewDetector(config.Config{
		Rules: map[string]config.Rule{
			rule.RuleID: *rule,
		},
		Keywords: rule.Keywords,
	})
}

func init() {
	/* generated with following python code:
	```python
	import os
	import re

	exported_function_pattern = re.compile(r"func\s+([A-Z][a-zA-Z0-9]*)\s*\(")

	def get_exported_functions(dir_path):
	    exported_functions = set()
	    for root, dirs, files in os.walk(dir_path):
	        for file_name in files:
	            if file_name.endswith(".go"):
	                file_path = os.path.join(root, file_name)
	                with open(file_path, "r") as f:
	                    content = f.read()
	                    matches = exported_function_pattern.findall(content)
	                    for match in matches:
	                        exported_functions.add(match)
	    return exported_functions

	if __name__ == "__main__":
	    dir_path = "cmd/generate/config/rules"
	    exported_functions = get_exported_functions(dir_path)
	    print("Exported functions:")
	    for func_name in sorted(exported_functions):
	        if func_name != "GCPServiceAccount": # this is no used
	            print("addRule(rules." + func_name + "())")
	```
	*/

	addRule(rules.AWS())
	addRule(rules.AdafruitAPIKey())
	addRule(rules.AdobeClientID())
	addRule(rules.AdobeClientSecret())
	addRule(rules.AgeSecretKey())
	addRule(rules.Airtable())
	addRule(rules.AlgoliaApiKey())
	addRule(rules.AlibabaAccessKey())
	addRule(rules.AlibabaSecretKey())
	addRule(rules.AsanaClientID())
	addRule(rules.AsanaClientSecret())
	addRule(rules.Atlassian())
	addRule(rules.Authress())
	addRule(rules.Beamer())
	addRule(rules.BitBucketClientID())
	addRule(rules.BitBucketClientSecret())
	addRule(rules.BittrexAccessKey())
	addRule(rules.BittrexSecretKey())
	addRule(rules.Clojars())
	addRule(rules.CodecovAccessToken())
	addRule(rules.CoinbaseAccessToken())
	addRule(rules.ConfluentAccessToken())
	addRule(rules.ConfluentSecretKey())
	addRule(rules.Contentful())
	addRule(rules.Databricks())
	addRule(rules.DatadogtokenAccessToken())
	addRule(rules.DefinedNetworkingAPIToken())
	addRule(rules.DigitalOceanOAuthToken())
	addRule(rules.DigitalOceanPAT())
	addRule(rules.DigitalOceanRefreshToken())
	addRule(rules.DiscordAPIToken())
	addRule(rules.DiscordClientID())
	addRule(rules.DiscordClientSecret())
	addRule(rules.Doppler())
	addRule(rules.DroneciAccessToken())
	addRule(rules.DropBoxAPISecret())
	addRule(rules.DropBoxLongLivedAPIToken())
	addRule(rules.DropBoxShortLivedAPIToken())
	addRule(rules.Duffel())
	addRule(rules.Dynatrace())
	addRule(rules.EasyPost())
	addRule(rules.EasyPostTestAPI())
	addRule(rules.EtsyAccessToken())
	addRule(rules.Facebook())
	addRule(rules.FastlyAPIToken())
	addRule(rules.FinicityAPIToken())
	addRule(rules.FinicityClientSecret())
	addRule(rules.FinnhubAccessToken())
	addRule(rules.FlickrAccessToken())
	addRule(rules.FlutterwaveEncKey())
	addRule(rules.FlutterwavePublicKey())
	addRule(rules.FlutterwaveSecretKey())
	addRule(rules.FrameIO())
	addRule(rules.FreshbooksAccessToken())
	addRule(rules.GCPAPIKey())
	addRule(rules.GenericCredential())
	addRule(rules.GitHubApp())
	addRule(rules.GitHubFineGrainedPat())
	addRule(rules.GitHubOauth())
	addRule(rules.GitHubPat())
	addRule(rules.GitHubRefresh())
	addRule(rules.GitlabPat())
	addRule(rules.GitlabPipelineTriggerToken())
	addRule(rules.GitlabRunnerRegistrationToken())
	addRule(rules.GitterAccessToken())
	addRule(rules.GoCardless())
	addRule(rules.GrafanaApiKey())
	addRule(rules.GrafanaCloudApiToken())
	addRule(rules.GrafanaServiceAccountToken())
	addRule(rules.Hashicorp())
	addRule(rules.Heroku())
	addRule(rules.HubSpot())
	addRule(rules.Intercom())
	addRule(rules.JWT())
	addRule(rules.KrakenAccessToken())
	addRule(rules.KucoinAccessToken())
	addRule(rules.KucoinSecretKey())
	addRule(rules.LaunchDarklyAccessToken())
	addRule(rules.LinearAPIToken())
	addRule(rules.LinearClientSecret())
	addRule(rules.LinkedinClientID())
	addRule(rules.LinkedinClientSecret())
	addRule(rules.LobAPIToken())
	addRule(rules.LobPubAPIToken())
	addRule(rules.MailChimp())
	addRule(rules.MailGunPrivateAPIToken())
	addRule(rules.MailGunPubAPIToken())
	addRule(rules.MailGunSigningKey())
	addRule(rules.MapBox())
	addRule(rules.MattermostAccessToken())
	addRule(rules.MessageBirdAPIToken())
	addRule(rules.MessageBirdClientID())
	addRule(rules.NPM())
	addRule(rules.NetlifyAccessToken())
	addRule(rules.NewRelicBrowserAPIKey())
	addRule(rules.NewRelicUserID())
	addRule(rules.NewRelicUserKey())
	addRule(rules.NytimesAccessToken())
	addRule(rules.OktaAccessToken())
	addRule(rules.OpenAI())
	addRule(rules.PlaidAccessID())
	addRule(rules.PlaidAccessToken())
	addRule(rules.PlaidSecretKey())
	addRule(rules.PlanetScaleAPIToken())
	addRule(rules.PlanetScaleOAuthToken())
	addRule(rules.PlanetScalePassword())
	addRule(rules.PostManAPI())
	addRule(rules.Prefect())
	addRule(rules.PrivateKey())
	addRule(rules.PulumiAPIToken())
	addRule(rules.PyPiUploadToken())
	addRule(rules.RapidAPIAccessToken())
	addRule(rules.ReadMe())
	addRule(rules.RubyGemsAPIToken())
	addRule(rules.SendGridAPIToken())
	addRule(rules.SendInBlueAPIToken())
	addRule(rules.SendbirdAccessID())
	addRule(rules.SendbirdAccessToken())
	addRule(rules.SentryAccessToken())
	addRule(rules.ShippoAPIToken())
	addRule(rules.ShopifyAccessToken())
	addRule(rules.ShopifyCustomAccessToken())
	addRule(rules.ShopifyPrivateAppAccessToken())
	addRule(rules.ShopifySharedSecret())
	addRule(rules.SidekiqSecret())
	addRule(rules.SidekiqSensitiveUrl())
	addRule(rules.SlackAppLevelToken())
	addRule(rules.SlackBotToken())
	addRule(rules.SlackConfigurationRefreshToken())
	addRule(rules.SlackConfigurationToken())
	addRule(rules.SlackLegacyBotToken())
	addRule(rules.SlackLegacyToken())
	addRule(rules.SlackLegacyWorkspaceToken())
	addRule(rules.SlackUserToken())
	addRule(rules.SlackWebHookUrl())
	addRule(rules.Snyk())
	addRule(rules.SquareAccessToken())
	addRule(rules.SquareSecret())
	addRule(rules.SquareSpaceAccessToken())
	addRule(rules.StripeAccessToken())
	addRule(rules.SumoLogicAccessID())
	addRule(rules.SumoLogicAccessToken())
	addRule(rules.TeamsWebhook())
	addRule(rules.TelegramBotToken())
	addRule(rules.TravisCIAccessToken())
	addRule(rules.TrelloAccessToken())
	addRule(rules.Twilio())
	addRule(rules.TwitchAPIToken())
	addRule(rules.TwitterAPIKey())
	addRule(rules.TwitterAPISecret())
	addRule(rules.TwitterAccessSecret())
	addRule(rules.TwitterAccessToken())
	addRule(rules.TwitterBearerToken())
	addRule(rules.Typeform())
	addRule(rules.VaultBatchToken())
	addRule(rules.VaultServiceToken())
	addRule(rules.YandexAPIKey())
	addRule(rules.YandexAWSAccessToken())
	addRule(rules.YandexAccessToken())
	addRule(rules.ZendeskSecretKey())
}
