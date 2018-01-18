package au.edu.qcif.xnat.auth.openid;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.nrg.framework.annotations.XnatPlugin;
import org.nrg.framework.configuration.ConfigPaths;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.MessageSource;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;
import au.edu.qcif.xnat.auth.openid.OpenIdConnectFilter;
import org.nrg.xnat.security.provider.AuthenticationProviderConfigurationLocator;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Properties;
import org.springframework.security.web.authentication.preauth.AbstractPreAuthenticatedProcessingFilter;
import org.springframework.security.oauth2.client.filter.OAuth2ClientContextFilter;
import org.nrg.xnat.security.XnatSecurityExtension;

@XnatPlugin(value = "xnat-openid-auth-plugin", name = "XNAT OpenID Authentication Provider Plugin")
@EnableOAuth2Client
@EnableWebSecurity
@Component
public class OpenIdAuthPlugin implements XnatSecurityExtension {

	@Autowired
	public void setSiteConfigPreferences(final SiteConfigPreferences preferences) {
		_preferences = preferences;
	}

	@Autowired
	public void setConfigPaths(final ConfigPaths configPaths) {
		_configPaths = configPaths;
	}

	@Autowired
	public void setMessageSource(final MessageSource messageSource) {
		_messageSource = messageSource;
	}

	@Bean
	public OAuth2ProtectedResourceDetails googleOpenId() {
		return getProtectedResourceDetails("google");
	}

	@Bean
	public OAuth2ProtectedResourceDetails aafOpenId() {
		return getProtectedResourceDetails("aaf");
	}

	private AuthorizationCodeResourceDetails getProtectedResourceDetails(String providerId) {
		final String clientId = getProperty(providerId, "clientId");
		final String clientSecret = getProperty(providerId, "clientSecret");
		final String accessTokenUri = getProperty(providerId, "accessTokenUri");
		final String userAuthUri = getProperty(providerId, "userAuthUri");
		final String preEstablishedUri = _props.getProperty("siteUrl")
				+ getProperty(providerId, "preEstablishedRedirUri");
		final String[] scopes = getProperty(providerId, "scopes").split(",");
		final AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
		details.setClientId(clientId);
		details.setClientSecret(clientSecret);
		details.setAccessTokenUri(accessTokenUri);
		details.setUserAuthorizationUri(userAuthUri);
		details.setScope(Arrays.asList(scopes));
		details.setPreEstablishedRedirectUri(preEstablishedUri);
		details.setUseCurrentUri(false);
		return details;
	}

	private boolean isEnabled(String providerId) {
		getEnabledProviders();
		for (String provider : _enabledProviders) {
			if (provider.equals(providerId)) {
				return true;
			}
		}
		return false;
	}

	public String getProperty(String providerId, String propName) {
		loadProps();
		return _props.getProperty(_id + "." + providerId + "." + propName);
	}

	private void loadProps() {
		if (_props == null) {
			AuthenticationProviderConfigurationLocator configLocator = openIdConfigLocator();
			_props = configLocator.getProviderDefinitions().get("openid");
			_inst = this;
		}
	}

	public Properties getProps() {
		return _props;
	}

	public String[] getEnabledProviders() {
		if (_enabledProviders == null) {
			_enabledProviders = _props.getProperty("enabled").split(",");
		}
		return _enabledProviders;
	}

	@Autowired
	@Qualifier("googleOpenIdTemplate")
	private OAuth2RestTemplate googleRestTemplate;

	@Autowired
	@Qualifier("aafOpenIdTemplate")
	private OAuth2RestTemplate aafRestTemplate;

	@Bean
	public OpenIdConnectFilter googleOpenIdConnectFilter() {
		OpenIdConnectFilter filter = new OpenIdConnectFilter("/google-login", "google", this);
		filter.setRestTemplate(googleRestTemplate);
		return filter;
	}

	@Bean
	public OpenIdConnectFilter aafOpenIdConnectFilter() {
		OpenIdConnectFilter filter = new OpenIdConnectFilter("/openid-login", "aaf", this);
		filter.setRestTemplate(aafRestTemplate);
		return filter;
	}

	@Bean
	@Scope(value = WebApplicationContext.SCOPE_SESSION, proxyMode = ScopedProxyMode.TARGET_CLASS)
	public OAuth2RestTemplate googleOpenIdTemplate(final OAuth2ClientContext clientContext) {
		final OAuth2RestTemplate template = new OAuth2RestTemplate(googleOpenId(), clientContext);
		return template;
	}

	@Bean
	@Scope(value = WebApplicationContext.SCOPE_SESSION, proxyMode = ScopedProxyMode.TARGET_CLASS)
	public OAuth2RestTemplate aafOpenIdTemplate(final OAuth2ClientContext clientContext) {
		final OAuth2RestTemplate template = new OAuth2RestTemplate(aafOpenId(), clientContext);
		return template;
	}

	@Bean
	public AuthenticationProviderConfigurationLocator openIdConfigLocator() {
		return new AuthenticationProviderConfigurationLocator(_id, _configPaths, _messageSource);
	}

	public void configure(final HttpSecurity http) throws Exception {
		http.addFilterAfter(new OAuth2ClientContextFilter(), AbstractPreAuthenticatedProcessingFilter.class)
				.addFilterAfter(googleOpenIdConnectFilter, OAuth2ClientContextFilter.class)
				.addFilterAfter(aafOpenIdConnectFilter, OAuth2ClientContextFilter.class);
	}

	@Autowired
	@Qualifier("googleOpenIdConnectFilter")
	private OpenIdConnectFilter googleOpenIdConnectFilter;

	@Autowired
	@Qualifier("aafOpenIdConnectFilter")
	private OpenIdConnectFilter aafOpenIdConnectFilter;

	private SiteConfigPreferences _preferences;
	private ConfigPaths _configPaths;
	private MessageSource _messageSource;
	private static String _id = "openid";
	private Properties _props;
	private String[] _enabledProviders;
	private static OpenIdAuthPlugin _inst;

	public static Properties getConfig() {
		return _inst.getProps();
	}

	public static String getLoginStr() {
		String[] enabledProviders = _inst.getEnabledProviders();
		String loginStr = "";
		int idx = 0;
		for (String enabledProvider : enabledProviders) {
			loginStr = loginStr + _inst.getProperty(enabledProvider, "link");
		}
		return loginStr;
	}

	public void configure(final AuthenticationManagerBuilder builder) throws Exception {

	}

	public String getAuthMethod() {
		return _id;
	}
}
