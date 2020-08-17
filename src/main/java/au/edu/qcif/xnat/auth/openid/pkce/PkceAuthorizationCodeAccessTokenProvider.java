package au.edu.qcif.xnat.auth.openid.pkce;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Iterator;
import java.util.List;
import java.util.TreeMap;

import org.apache.commons.codec.binary.Base64;
import org.python.jline.internal.Log;
import org.springframework.http.HttpHeaders;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.oauth2.client.filter.state.DefaultStateKeyGenerator;
import org.springframework.security.oauth2.client.filter.state.StateKeyGenerator;
import org.springframework.security.oauth2.client.resource.OAuth2AccessDeniedException;
import org.springframework.security.oauth2.client.resource.OAuth2ProtectedResourceDetails;
import org.springframework.security.oauth2.client.resource.UserApprovalRequiredException;
import org.springframework.security.oauth2.client.resource.UserRedirectRequiredException;
import org.springframework.security.oauth2.client.token.AccessTokenRequest;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeAccessTokenProvider;
import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;
import org.springframework.security.oauth2.common.OAuth2AccessToken;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

public class PkceAuthorizationCodeAccessTokenProvider extends AuthorizationCodeAccessTokenProvider {

	private StateKeyGenerator stateKeyGenerator = new DefaultStateKeyGenerator();

	private boolean stateMandatory = true;

	public void setStateKeyGenerator(StateKeyGenerator stateKeyGenerator) {
		this.stateKeyGenerator = stateKeyGenerator;
	}

	public void setStateMandatory(boolean stateMandatory) {
		this.stateMandatory = stateMandatory;
	}

	@Override
	public OAuth2AccessToken obtainAccessToken(OAuth2ProtectedResourceDetails details, AccessTokenRequest request)
			throws UserRedirectRequiredException, UserApprovalRequiredException, AccessDeniedException,
			OAuth2AccessDeniedException {
		PkceAuthorizationCodeResourceDetails resource = (PkceAuthorizationCodeResourceDetails) details;

		if (request.getAuthorizationCode() == null) {
			if (request.getStateKey() == null) {
				throw getRedirectForAuthorization(resource, request);
			}
			obtainAuthorizationCode(resource, request);
		}
		return retrieveToken(request, resource, getParametersForTokenRequest(resource, request),
				getHeadersForTokenRequest(request));

	}

	private HttpHeaders getHeadersForTokenRequest(AccessTokenRequest request) {
		HttpHeaders headers = new HttpHeaders();
		// No cookie for token request
		return headers;
	}

	private MultiValueMap<String, String> getParametersForTokenRequest(AuthorizationCodeResourceDetails details,
			AccessTokenRequest request) {
		PkceAuthorizationCodeResourceDetails resource = (PkceAuthorizationCodeResourceDetails) details;

		MultiValueMap<String, String> form = new LinkedMultiValueMap<String, String>();
		form.set("grant_type", "authorization_code");
		form.set("code", request.getAuthorizationCode());

		PreservedState preservedState = (PreservedState) request.getPreservedState();

		if (resource.isPkceEnabled()) {
			form.set("code_verifier", preservedState.getCodeVerifier());
		}
		
		if (request.getStateKey() != null || stateMandatory) {
			// The token endpoint has no use for the state so we don't send it back, but we
			// are using it
			// for CSRF detection client side...
			if (preservedState == null) {
				throw new InvalidRequestException(
						"Possible CSRF detected - state parameter was required but no state could be found");
			}
		}

		// Extracting the redirect URI from a saved request should ignore the current
		// URI, so it's not simply a call to
		// resource.getRedirectUri()
		String redirectUri = null;

		// Get the redirect uri from the stored state
		if (preservedState != null && preservedState.getRedirectUri() != null) {
			// Use the preserved state in preference if it is there
			// TODO: treat redirect URI as a special kind of state (this is a historical mini hack)
			redirectUri = preservedState.getRedirectUri();
		}
		else {
			redirectUri = resource.getRedirectUri(request);
		}

		if (redirectUri != null && !"NONE".equals(redirectUri)) {
			form.set("redirect_uri", redirectUri);
		}

		return form;

	}

	private UserRedirectRequiredException getRedirectForAuthorization(AuthorizationCodeResourceDetails details,
			AccessTokenRequest request) {
		PkceAuthorizationCodeResourceDetails resource = (PkceAuthorizationCodeResourceDetails) details;

		// we don't have an authorization code yet. So first get that.
		TreeMap<String, String> requestParameters = new TreeMap<String, String>();
		requestParameters.put("response_type", "code"); // oauth2 spec, section 3
		requestParameters.put("client_id", resource.getClientId());

		String codeVerifier = null;
		if (resource.isPkceEnabled()) {
			codeVerifier = generateKey(96);
			try {
				String codeChallenge = createHash(codeVerifier);
				Log.error(codeChallenge);
				Log.error(codeChallenge.length());
				requestParameters.put("code_challenge", codeChallenge);
				requestParameters.put("code_challenge_method", "S256");
			} catch (Exception e) {
				requestParameters.put("code_challenge", codeVerifier);
			}
		}

		// Client secret is not required in the initial authorization request

		String redirectUri = resource.getRedirectUri(request);
		if (redirectUri != null) {
			requestParameters.put("redirect_uri", redirectUri);
		}

		if (resource.isScoped()) {

			StringBuilder builder = new StringBuilder();
			List<String> scope = resource.getScope();

			if (scope != null) {
				Iterator<String> scopeIt = scope.iterator();
				while (scopeIt.hasNext()) {
					builder.append(scopeIt.next());
					if (scopeIt.hasNext()) {
						builder.append(' ');
					}
				}
			}

			requestParameters.put("scope", builder.toString());
		}

		UserRedirectRequiredException redirectException = new UserRedirectRequiredException(
				resource.getUserAuthorizationUri(), requestParameters);

		String stateKey = stateKeyGenerator.generateKey(resource);
		redirectException.setStateKey(stateKey);
		request.setStateKey(stateKey);
		redirectException.setStateToPreserve(new PreservedState(redirectUri, codeVerifier));
		request.setPreservedState(new PreservedState(redirectUri, codeVerifier));

		return redirectException;

	}

	private static String createHash(String value) throws NoSuchAlgorithmException {
		MessageDigest md = MessageDigest.getInstance("SHA-256");
		byte[] digest = md.digest(value.getBytes(StandardCharsets.US_ASCII));
		return encodeToByte64String(digest);
	}

	private static String generateKey(int keyLength) {
		byte[] bytes = new byte[keyLength];
		SecureRandom random = new SecureRandom();
		random.nextBytes(bytes);
		return encodeToByte64String(bytes);
	}

	private static String encodeToByte64String(byte[] bytes) {
		final byte[] CHUNK_SEPARATOR = { '\r', '\n' };
		Base64 base64 = new Base64(0, CHUNK_SEPARATOR, true);
		String base64Encoded = base64.encodeAsString(bytes);
		return base64Encoded;
	}
	
	static class PreservedState {
		private String redirectUri;

		private String codeVerifier;
		
		public PreservedState(String redirectUri, String codeVerifier) {
			this.redirectUri = redirectUri;
			this.codeVerifier = codeVerifier;
		}

		public String getRedirectUri() {
			return redirectUri;
		}

		public void setRedirectUri(String redirectUri) {
			this.redirectUri = redirectUri;
		}
		
		public String getCodeVerifier() {
			return codeVerifier;
		}

		public void setCodeVerifier(String codeVerifier) {
			this.codeVerifier = codeVerifier;
		}
	}
}
