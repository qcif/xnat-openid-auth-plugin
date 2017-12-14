package au.edu.qcif.xnat.auth.openid;

import java.io.IOException;
import java.util.Map;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

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

public class OpenIdConnectFilter extends AbstractAuthenticationProcessingFilter {
    public OAuth2RestOperations restTemplate;

    public OpenIdConnectFilter(String defaultFilterProcessesUrl) {
        super(defaultFilterProcessesUrl);
        System.out.println("Created OpenIdConnectFilter...");
        setAuthenticationManager(new NoopAuthenticationManager());
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
    	System.out.println("Executed attemptAuthentication...");
        OAuth2AccessToken accessToken;
        try {
        	System.out.println("Getting access token...");
            accessToken = restTemplate.getAccessToken();
            System.out.println("Got access token!!!");
            System.out.println(accessToken);
        } catch (final OAuth2Exception e) {
        	System.out.println("Could not obtain access token");
        	System.out.println(e);
        	System.out.println("<<---------------------------->>");
        	e.printStackTrace();
            throw new BadCredentialsException("Could not obtain access token", e);
        } catch (final RuntimeException ex2) {
        	System.out.println("Runtime exception");
        	System.out.println(ex2);
        	System.out.println("----------------------------");
        	ex2.printStackTrace();
        	throw ex2;
        }
        try {
        	System.out.println("Getting idToken...");
            final String idToken = accessToken.getAdditionalInformation().get("id_token").toString();
            final Jwt tokenDecoded = JwtHelper.decode(idToken);
            System.out.println("===== : " + tokenDecoded.getClaims());

            final Map<String, String> authInfo = new ObjectMapper().readValue(tokenDecoded.getClaims(), Map.class);

            final OpenIdConnectUserDetails user = new OpenIdConnectUserDetails(authInfo, accessToken);
            System.out.println("Created OPenIDCOnnectUserDetails....");
            return new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
        } catch (final InvalidTokenException e) {
            throw new BadCredentialsException("Could not obtain user details from token", e);
        }

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