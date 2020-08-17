package au.edu.qcif.xnat.auth.openid.pkce;

import org.springframework.security.oauth2.client.token.grant.code.AuthorizationCodeResourceDetails;

public class PkceAuthorizationCodeResourceDetails extends AuthorizationCodeResourceDetails {
	private boolean pkceEnabled;
	
	public PkceAuthorizationCodeResourceDetails() {
		super();
	}

	public boolean isPkceEnabled() {
		return pkceEnabled;
	}

	public void setPkceEnabled(boolean pkceEnabled) {
		this.pkceEnabled = pkceEnabled;
	}
}
