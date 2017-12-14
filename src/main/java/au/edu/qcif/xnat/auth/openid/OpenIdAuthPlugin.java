package au.edu.qcif.xnat.auth.openid;

import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.nrg.framework.annotations.XnatPlugin;
import org.nrg.xdat.preferences.SiteConfigPreferences;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.stereotype.Component;
import org.springframework.web.context.WebApplicationContext;

import java.util.Arrays;

@XnatPlugin(value = "xnat-openid-auth-plugin", name = "XNAT OpenID Authentication Provider Plugin")
@EnableOAuth2Client
@Component
public class OpenIdAuthPlugin {

	 @Autowired
	    public void setSiteConfigPreferences(final SiteConfigPreferences preferences) {
	        _preferences = preferences;
	    }
	 
	@Autowired
    @Qualifier("googleOpenIdTemplate")
    private OAuth2RestTemplate restTemplate;
    
    @Bean
    public OpenIdConnectFilter googleOpenIdConnectFilter() {
    	OpenIdConnectFilter filter = new OpenIdConnectFilter("/google-login");
    	filter.setRestTemplate(restTemplate);
    	return filter;
    }
    
    @Bean
    public OAuth2ProtectedResourceDetails googleOpenId() {
    	
    	final String clientId = "";
    	final String clientSecret = "";
    	final String accessTokenUri = "";
    	final String userAuthUri = "";
    	final String preEstablishedUri ="";
        final AuthorizationCodeResourceDetails details = new AuthorizationCodeResourceDetails();
        details.setClientId(clientId);
        details.setClientSecret(clientSecret);
        details.setAccessTokenUri(accessTokenUri);
        details.setUserAuthorizationUri(userAuthUri);
//        details.setScope(scope);
        
        details.setScope(Arrays.asList("openid", "email"));
        details.setPreEstablishedRedirectUri(preEstablishedUri);
        details.setUseCurrentUri(false);
        
        return details;
    }
    
    @Bean
    @Scope(value = WebApplicationContext.SCOPE_SESSION, proxyMode = ScopedProxyMode.TARGET_CLASS)
    public OAuth2RestTemplate googleOpenIdTemplate(final OAuth2ClientContext clientContext) {
        final OAuth2RestTemplate template = new OAuth2RestTemplate(googleOpenId(), clientContext);
        return template;
    }
    
    private SiteConfigPreferences _preferences;
}
