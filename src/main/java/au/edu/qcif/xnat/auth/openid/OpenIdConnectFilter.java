/*
 *Copyright (C) 2018 Queensland Cyber Infrastructure Foundation (http://www.qcif.edu.au/)
 *
 *This program is free software: you can redistribute it and/or modify
 *it under the terms of the GNU General Public License as published by
 *the Free Software Foundation; either version 2 of the License, or
 *(at your option) any later version.
 *
 *This program is distributed in the hope that it will be useful,
 *but WITHOUT ANY WARRANTY; without even the implied warranty of
 *MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *GNU General Public License for more details.
 *
 *You should have received a copy of the GNU General Public License along
 *with this program; if not, write to the Free Software Foundation, Inc.,
 *51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */
package au.edu.qcif.xnat.auth.openid;

import java.io.IOException;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.nrg.xdat.security.helpers.Roles;
import org.nrg.xdat.security.helpers.Users;
import org.nrg.xdat.security.user.exceptions.UserFieldMappingException;
import org.nrg.xdat.security.user.exceptions.UserInitException;
import org.nrg.xdat.security.user.exceptions.UserNotFoundException;
import org.nrg.xft.event.EventDetails;
import org.nrg.xft.event.EventUtils;
import org.nrg.xft.security.UserI;
import org.nrg.xft.utils.ValidationUtils.ValidationResultsI;
import org.nrg.xnat.security.exceptions.NewAutoAccountNotAutoEnabledException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Lazy;
import org.springframework.context.annotation.Scope;
import org.springframework.context.annotation.ScopedProxyMode;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.oauth2.client.OAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestOperations;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.common.exceptions.OAuth2Exception;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.web.context.WebApplicationContext;

import com.fasterxml.jackson.databind.ObjectMapper;

import au.edu.qcif.xnat.auth.openid.tokens.OpenIdAuthToken;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableOAuth2Client;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;

/**
 * Main Spring Security authentication filter.
 * 
 * @author <a href='https://github.com/shilob'>Shilo Banihit</a>
 * 
 */
@EnableOAuth2Client
@Slf4j
public class OpenIdConnectFilter extends AbstractAuthenticationProcessingFilter {

	private OpenIdAuthPlugin plugin;
	private String[] allowedDomains;

	@Autowired
	@Qualifier("createRestTemplate")
	private OAuth2RestTemplate restTemplate;

	public OpenIdConnectFilter(String defaultFilterProcessesUrl, OpenIdAuthPlugin plugin) {
		super(defaultFilterProcessesUrl);
		log.debug("Created filter for " + defaultFilterProcessesUrl);
		setAuthenticationManager(new NoopAuthenticationManager());
		// this.providerId = providerId;
		this.plugin = plugin;
	}

	@Autowired
	@Override
	public void setAuthenticationFailureHandler(final AuthenticationFailureHandler handler) {
		super.setAuthenticationFailureHandler(handler);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		log.debug("Executed attemptAuthentication...");
		OAuth2AccessToken accessToken;
		try {
			log.debug("Getting access token...");
			accessToken = restTemplate.getAccessToken();
			log.debug("Got access token!!! {}", accessToken);
		} catch (final OAuth2Exception e) {
			log.debug("Could not obtain access token", e);
			log.debug("<<---------------------------->>");
			e.printStackTrace();
			throw new BadCredentialsException("Could not obtain access token", e);
		} catch (final RuntimeException ex2) {
			log.debug("Runtime exception", ex2);
			log.debug("----------------------------");
			throw ex2;
		}
		String providerId = (String) request.getSession().getAttribute("providerId");
		try {
			log.debug("Getting idToken...");
			final String idToken = accessToken.getAdditionalInformation().get("id_token").toString();
			final Jwt tokenDecoded = JwtHelper.decode(idToken);
			log.debug("===== : " + tokenDecoded.getClaims());
			final Map<String, String> authInfo = new ObjectMapper().readValue(tokenDecoded.getClaims(), Map.class);
			final OpenIdConnectUserDetails user = new OpenIdConnectUserDetails(providerId, authInfo, accessToken);

			if (shouldFilterEmailDomains(providerId) && !isAllowedEmailDomain(user.getEmail(), providerId)) {
				log.error("Domain not allowed: " + user.getEmail());

				throw (AuthenticationException) (new NewAutoAccountNotAutoEnabledException(
						"New OpenID user, not on the domain whitelist.", user));
			}
			if (!plugin.isEnabled(providerId)) {
				log.error("Provider is disabled.");
				throw (AuthenticationException) (new NewAutoAccountNotAutoEnabledException(
						"OpenID user is not on the enabled list.", user));
			}
			log.debug("Checking if user exists...");
			UserI xdatUser;
			try {
				xdatUser = Users.getUser(user.getUsername());
				if (xdatUser.isEnabled()) {
					log.debug("User is enabled...");
					return new OpenIdAuthToken(xdatUser, "openid");
				} else {
					throw (AuthenticationException) (new NewAutoAccountNotAutoEnabledException(
							"New OpenID user, needs to to be enabled.", xdatUser));
				}
			} catch (UserInitException e1) {
				throw new BadCredentialsException("Cannot init OpenID User from DB.", e1);
			} catch (UserNotFoundException e0) {
				String userAutoEnabled = plugin.getProperty(providerId, "userAutoEnabled");
				String userAutoVerified = plugin.getProperty(providerId, "userAutoVerified");

				xdatUser = Users.createUser();
				xdatUser.setEmail(user.getEmail());
				xdatUser.setLogin(user.getUsername());
				xdatUser.setFirstname(user.getFirstname());
				xdatUser.setLastname(user.getLastname());
				xdatUser.setEnabled(userAutoEnabled);
				xdatUser.setVerified(userAutoVerified);

				if (Boolean.parseBoolean(plugin.getProperty(providerId, "forceUserCreate"))) {
					log.debug("User created, username: " + xdatUser.getUsername());
					log.debug("User id: " + xdatUser.getID());
					EventDetails ev = new EventDetails(EventUtils.CATEGORY.PROJECT_ACCESS, EventUtils.TYPE.PROCESS,
							"added new user", "new user logged in", "OpenID connect new user");
					try {
						UserI adminUser = Users.getUser("admin");
						Users.save(xdatUser, adminUser, true, ev);
					} catch (Exception e) {
						log.debug("Ignoring exception:");
						e.printStackTrace();
					}
				}
				if (Boolean.parseBoolean(userAutoEnabled)) {
					return new OpenIdAuthToken(xdatUser, "openid");
				}
				throw (AuthenticationException) (new NewAutoAccountNotAutoEnabledException(
						"New OpenID user, needs to to be enabled.", xdatUser));
			}
		} catch (final InvalidTokenException e) {
			throw new BadCredentialsException("Could not obtain user details from token", e);
		}

	}

	private boolean isAllowedEmailDomain(String email, String providerId) {
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

	private boolean shouldFilterEmailDomains(String providerId) {
		return Boolean.parseBoolean(plugin.getProperty(providerId, "shouldFilterEmailDomains"));
	}

	private static class NoopAuthenticationManager implements AuthenticationManager {

		@Override
		public Authentication authenticate(Authentication authentication) throws AuthenticationException {
			throw new UnsupportedOperationException("No authentication should be done with this AuthenticationManager");
		}

	}

}