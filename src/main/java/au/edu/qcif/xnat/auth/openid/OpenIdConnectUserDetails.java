package au.edu.qcif.xnat.auth.openid;

import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.Map;

import org.nrg.xdat.entities.UserAuthI;
import org.nrg.xdat.security.XDATUser;
import org.nrg.xft.exception.MetaDataException;
import org.nrg.xft.security.UserI;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.common.OAuth2AccessToken;

public class OpenIdConnectUserDetails extends XDATUser {

    private static final long serialVersionUID = 1L;

    private String userId;
    private String username;
    private OAuth2AccessToken token;
    private String email;

    public OpenIdConnectUserDetails(Map<String, String> userInfo, OAuth2AccessToken token) {
    	System.out.println(userInfo);
        this.userId = userInfo.get("sub");
        this.username = userInfo.get("email");
        this.token = token;
        this.email = userInfo.get("email");
    }

    @Override
    public String getUsername() {
        return username;
    }

    public String getUserId() {
        return userId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public OAuth2AccessToken getToken() {
        return token;
    }

    public void setToken(OAuth2AccessToken token) {
        this.token = token;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    @Override
    public String getPassword() {
        return null;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

	@Override
	public Integer getID() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getLogin() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isGuest() {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public String getFirstname() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getLastname() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getEmail() {
		return this.email;
	}

	@Override
	public String getDBName() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public Boolean isVerified() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public String getSalt() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public boolean isActive() throws MetaDataException {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public Date getLastModified() {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public void setLogin(String login) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setEmail(String e) {
		this.email = e;
	}

	@Override
	public void setFirstname(String firstname) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setLastname(String lastname) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setPassword(String encodePassword) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setSalt(String salt) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setPrimaryPassword_encrypt(Object b) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setEnabled(Object enabled) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void setVerified(Object verified) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public UserAuthI setAuthorization(UserAuthI newUserAuth) {
		// TODO Auto-generated method stub
		return null;
	}

	@Override
	public UserAuthI getAuthorization() {
		// TODO Auto-generated method stub
		return null;
	}

}
