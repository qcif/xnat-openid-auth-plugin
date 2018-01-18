package au.edu.qcif.xnat.auth.openid.tokens;

import org.nrg.xft.security.UserI;
import org.nrg.xnat.security.tokens.AbstractXnatAuthenticationToken;
import org.springframework.security.core.SpringSecurityCoreVersion;

public class OpenIdAuthToken extends AbstractXnatAuthenticationToken {

	/**
	 * 
	 */
	private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;;

	public OpenIdAuthToken(final UserI details, final String providerId) {
		super(providerId, details, null, details.getAuthorities());
	}

	public String toString() {
		return getPrincipal() + ": " + getProviderId();
	}

}
