package au.edu.qcif.xnat.auth.openid;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static java.nio.charset.Charset.defaultCharset;
import static org.junit.Assert.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.junit.WireMockRule;
import lombok.extern.slf4j.Slf4j;
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
import org.springframework.core.io.ClassPathResource;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.MacSigner;
import org.springframework.security.oauth2.client.DefaultOAuth2ClientContext;
import org.springframework.security.oauth2.client.OAuth2RestTemplate;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.DefaultAccessTokenRequest;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

@Slf4j
@SuppressWarnings("deprecation")
public class OpenIdConnectFilterTest {
    private static final String CSRF_STATE = "CSRF-state";

    private final ObjectMapper           objectMapper;
    private final UserManagementServiceI userManagementService;
    private final OpenIdConnectFilter    subject;

    @Rule
    public final WireMockRule wireMockRule = new WireMockRule(8080);

    public OpenIdConnectFilterTest() throws IOException {
        final OpenIdAuthPlugin plugin = new OpenIdAuthPlugin();
        plugin.setAuthenticationProviderConfigurationLocator(new AuthenticationProviderConfigurationLocator(new ConfigPaths(Collections.singletonList(Paths.get(new ClassPathResource("config").getURI()))), null));

        objectMapper = new ObjectMapper();
        userManagementService = mock(UserManagementServiceI.class);
        subject = new OpenIdConnectFilter("/openid-login", plugin) {
            @Override
            protected UserManagementServiceI getUserManagementServiceInstance() {
                return userManagementService;
            }
        };

        final MockHttpServletRequest mockRequest = new MockHttpServletRequest();
        mockRequest.setParameter("providerId", "test");
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(mockRequest));

        final Map<String, String[]> parameters = new HashMap<>();
        parameters.put("state", new String[]{CSRF_STATE});

        final AccessTokenRequest accessTokenRequest = new DefaultAccessTokenRequest(parameters);
        accessTokenRequest.setPreservedState(CSRF_STATE);

        final DefaultOAuth2ClientContext clientContext = new DefaultOAuth2ClientContext(accessTokenRequest);
        clientContext.setPreservedState(CSRF_STATE, CSRF_STATE);

        final OAuth2RestTemplate restTemplate = plugin.createRestTemplate(clientContext);
        ReflectionTestUtils.setField(subject, "restTemplate", restTemplate);
    }

    @Test
    public void attemptAuthentication() throws Exception {
        stubFor(post(urlEqualTo("/auth")).willReturn(aResponse().withStatus(302)
                                                                .withHeader("Location", "http://localhost:8080?code=code")));

        final String idToken = JwtHelper.encode(readFile("id_token.json"),
                                                new MacSigner("secret")).getEncoded();

        final Map<String, Object> body = new HashMap<>();
        body.put("access_token", "test-token");
        body.put("id_token", idToken);
        final String json = objectMapper.writeValueAsString(body);

        stubFor(post(urlEqualTo("/token")).willReturn(aResponse()
                                                              .withStatus(200)
                                                              .withHeader("Content-Type", "application/json")
                                                              .withBody(json)));
        stubFor(get(urlEqualTo("/userinfo")).willReturn(aResponse()
                                                                .withStatus(200)
                                                                .withHeader("Content-Type", "application/json")
                                                                .withBody(readFile("user_info.json"))));

        final HttpServletRequest  request  = new MockHttpServletRequest();
        final HttpServletResponse response = new MockHttpServletResponse();

        request.getSession().setAttribute("providerId", "test");

        when(userManagementService.getUser("test_1234567890")).thenThrow(UserNotFoundException.class);

        final UserI user = mock(UserI.class);
        when(userManagementService.createUser()).thenReturn(user);

        subject.attemptAuthentication(request, response);

        final ArgumentCaptor<String> argumentCaptor = ArgumentCaptor.forClass(String.class);
        Mockito.verify(user).setEmail(argumentCaptor.capture());

        final String email = argumentCaptor.getValue();
        assertEquals("john.doe@example.org", email);
    }

    private String readFile(String fileName) throws IOException {
        return IOUtils.toString(new ClassPathResource(fileName).getInputStream(), defaultCharset());
    }
}
