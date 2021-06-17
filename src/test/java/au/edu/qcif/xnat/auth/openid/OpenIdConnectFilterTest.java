package au.edu.qcif.xnat.auth.openid;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.junit.WireMockRule;

import org.apache.commons.io.IOUtils;
import org.junit.Rule;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;
import org.nrg.framework.configuration.ConfigPaths;
import org.nrg.xdat.security.services.UserManagementServiceI;
import org.nrg.xdat.security.user.exceptions.UserNotFoundException;
import org.nrg.xft.security.UserI;
import org.nrg.xnat.security.provider.AuthenticationProviderConfigurationLocator;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;

import au.edu.qcif.xnat.auth.openid.pkce.PkceAuthorizationCodeAccessTokenProvider;

import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static java.nio.charset.Charset.defaultCharset;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class OpenIdConnectFilterTest {

    private OpenIdConnectFilter subject;
    private ObjectMapper objectMapper = new ObjectMapper();

    @Rule
    public WireMockRule wireMockRule = new WireMockRule(8080);
    private UserManagementServiceI userManagementService = mock(UserManagementServiceI.class);

    public OpenIdConnectFilterTest() throws IOException {
        System.setProperty("xnat.home", System.getProperty("user.dir"));

        OpenIdAuthPlugin plugin = new OpenIdAuthPlugin();
        URI uri = new ClassPathResource("config").getURI();
        ConfigPaths configPaths = new ConfigPaths(Collections.singletonList(Paths.get(uri)));
        AuthenticationProviderConfigurationLocator authenticationProviderConfigurationLocator =
                new AuthenticationProviderConfigurationLocator(configPaths, null);
        plugin.setAuthenticationProviderConfigurationLocator(authenticationProviderConfigurationLocator);

        subject = new OpenIdConnectFilter("/openid-login", plugin) {
            @Override
            protected UserManagementServiceI getUserManagementServiceInstance() {
                return userManagementService;
            }
        };

        HttpServletRequest mockRequest = new MockHttpServletRequest();

        ((MockHttpServletRequest) mockRequest).setParameter("providerId", "test");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(mockRequest));

        Map<String, String[]> parameters = new HashMap<>();
        String csrfState = "CSRF-state";
        parameters.put("state", new String[]{csrfState});

        AccessTokenRequest accessTokenRequest = new DefaultAccessTokenRequest(parameters);
        accessTokenRequest.setPreservedState(csrfState);

        DefaultOAuth2ClientContext clientContext = new DefaultOAuth2ClientContext(accessTokenRequest);
        clientContext.setPreservedState(csrfState, csrfState);

        OAuth2RestTemplate restTemplate = plugin.createRestTemplate(clientContext);
        ReflectionTestUtils.setField(subject, "restTemplate", restTemplate);

    }

    @Test
    public void attemptAuthentication() throws Exception {
        stubFor(post(urlEqualTo("/auth")).willReturn(aResponse().withStatus(302)
                .withHeader("Location", "http://localhost:8080?code=code")));

        String idToken = JwtHelper.encode(readFile("id_token.json"),
                new MacSigner("secret")).getEncoded();

        Map<String, Object> body = new HashMap<>();
        body.put("access_token", "test-token");
        body.put("id_token", idToken);
        String json = objectMapper.writeValueAsString(body);

        stubFor(post(urlEqualTo("/token")).willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(json)));
        stubFor(get(urlEqualTo("/userinfo")).willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody(readFile("user_info.json"))));

        HttpServletRequest request = (HttpServletRequest) new MockHttpServletRequest();
        HttpServletResponse response = (HttpServletResponse) new MockHttpServletResponse();

        request.getSession().setAttribute("providerId", "test");

        when(this.userManagementService.getUser("test_1234567890")).thenThrow(UserNotFoundException.class);
        UserI user = mock(UserI.class);
        when(this.userManagementService.createUser()).thenReturn(user);

        subject.attemptAuthentication(request, response);

        ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);
        Mockito.verify(user).setEmail(argumentCaptor.capture());

        String email = argumentCaptor.getValue();
        assertEquals("john.doe@example.org", email);
    }

    private String readFile(String fileName) throws IOException {
        return IOUtils.toString(new ClassPathResource(fileName).getInputStream(), defaultCharset());
    }
}
