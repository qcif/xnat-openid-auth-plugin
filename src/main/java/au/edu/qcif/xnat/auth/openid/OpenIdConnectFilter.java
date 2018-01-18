package au.edu.qcif.xnat.auth.openid;

import java.io.IOException;
import java.util.Arrays;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nrg.xdat.security.helpers.Users;
import org.nrg.xdat.security.user.exceptions.UserFieldMappingException;
import org.nrg.xdat.security.user.exceptions.UserInitException;
import org.nrg.xdat.security.user.exceptions.UserNotFoundException;
import org.nrg.xft.event.EventDetails;
import org.nrg.xft.event.EventUtils;
import org.nrg.xft.security.UserI;
import org.nrg.xnat.security.exceptions.NewAutoAccountNotAutoEnabledException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

import com.fasterxml.jackson.databind.ObjectMapper;

import au.edu.qcif.xnat.auth.openid.tokens.OpenIdAuthToken;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class OpenIdConnectFilter extends AbstractAuthenticationProcessingFilter {

	private final Log log = LogFactory.getLog(OpenIdConnectFilter.class);
	private String providerId;
	private OpenIdAuthPlugin plugin;
	public OAuth2RestOperations restTemplate;
	private String[] allowedDomains;

	public OpenIdConnectFilter(String defaultFilterProcessesUrl, String providerId, OpenIdAuthPlugin plugin) {
		super(defaultFilterProcessesUrl);
		setAuthenticationManager(new NoopAuthenticationManager());
		this.providerId = providerId;
		this.plugin = plugin;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		log.debug("Executed attemptAuthentication...");
		OAuth2AccessToken accessToken;
		try {
			log.debug("Getting access token...");
			accessToken = restTemplate.getAccessToken();
			log.debug("Got access token!!!");
			log.debug(accessToken);
		} catch (final OAuth2Exception e) {
			log.debug("Could not obtain access token");
			log.debug(e);
			log.debug("<<---------------------------->>");
			e.printStackTrace();
			throw new BadCredentialsException("Could not obtain access token", e);
		} catch (final RuntimeException ex2) {
			log.debug("Runtime exception");
			log.debug(ex2);
			log.debug("----------------------------");
			ex2.printStackTrace();
			throw ex2;
		}
		try {
			log.debug("Getting idToken...");
			final String idToken = accessToken.getAdditionalInformation().get("id_token").toString();
			final Jwt tokenDecoded = JwtHelper.decode(idToken);
			log.debug("===== : " + tokenDecoded.getClaims());
			final Map<String, String> authInfo = new ObjectMapper().readValue(tokenDecoded.getClaims(), Map.class);
			final OpenIdConnectUserDetails user = new OpenIdConnectUserDetails(authInfo, accessToken);

			if (shouldFilterEmailDomains() && !isAllowedEmailDomain(user.getEmail())) {
				log.debug("Domain not allowed: " + user.getEmail());

				throw new BadCredentialsException(
						plugin.getProperty(providerId, "openid.aaf.disallowedEmailDomainsMessage"));
			}

			log.debug("Created OPenIDCOnnectUserDetails....checking if user exists...");

			UserI xdatUser;
			try {
				xdatUser = Users.getUser(user.getUsername());
				if (xdatUser.isEnabled()) {
					log.debug("User is enabled...");
					return new OpenIdAuthToken(xdatUser, "openid");
				} else {
					throw new BadCredentialsException("OpenID User is disabled.");
				}
			} catch (UserInitException e1) {
				throw new BadCredentialsException("Cannot init OpenID User from DB.", e1);
			} catch (UserNotFoundException e0) {
				xdatUser = Users.createUser();
				xdatUser.setEmail(user.getEmail());
				xdatUser.setLogin(user.getUsername());
				xdatUser.setFirstname(user.getFirstname());
				xdatUser.setLastname(user.getLastname());

				log.debug("User created, username: " + xdatUser.getUsername());
				log.debug("User id: " + xdatUser.getID());
				EventDetails ev = new EventDetails(EventUtils.CATEGORY.PROJECT_ACCESS, EventUtils.TYPE.PROCESS,
						"added new user", "new user logged in", "OpenID connect new user");
				try {
					Users.save(xdatUser, null, true, ev);
				} catch (Exception e) {
					log.debug("Ignoring exception:");
					e.printStackTrace();
				}
				return new OpenIdAuthToken(xdatUser, "openid");
			}
		} catch (final InvalidTokenException e) {
			throw new BadCredentialsException("Could not obtain user details from token", e);
		}

	}

	private boolean isAllowedEmailDomain(String email) {
		if (allowedDomains == null) {
			allowedDomains = plugin.getProperty(providerId, "allowedEmailDomains").split(",");
		}
		String[] emailParts = email.split("@");
		String domain = emailParts.length >= 2 ? emailParts[1] : null;
		for (String allowedDomain : allowedDomains) {
			if (allowedDomain.equalsIgnoreCase(domain)) {
				return true;
			}
		}
		return false;
	}

	private boolean shouldFilterEmailDomains() {
		return Boolean.parseBoolean(plugin.getProperty(providerId, "shouldFilterEmailDomains"));
	}

	public void setRestTemplate(OAuth2RestTemplate restTemplate2) {
		restTemplate = restTemplate2;

	}

	private static class NoopAuthenticationManager implements AuthenticationManager {

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			throw new UnsupportedOperationException("No authentication should be done with this AuthenticationManager");
		}

	}
}