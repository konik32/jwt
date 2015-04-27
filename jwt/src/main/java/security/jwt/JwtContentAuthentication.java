package security.jwt;

import java.util.Collection;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

public class JwtContentAuthentication implements Authentication {

	/**
	 * 
	 */
	private static final long serialVersionUID = -7803929557239026111L;

	private JwtContent jwtContet;

	public JwtContentAuthentication(JwtContent jwtContet) {
		this.jwtContet = jwtContet;
	}

	private boolean authenticated = true;

	@Override
	public String getName() {
		return jwtContet.getName();
	}

	@Override
	public Collection<? extends GrantedAuthority> getAuthorities() {
		return jwtContet.getAuthorities();
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public Object getDetails() {
		return jwtContet;
	}

	@Override
	public Object getPrincipal() {
		return jwtContet;
	}

	@Override
	public boolean isAuthenticated() {
		return authenticated;
	}

	@Override
	public void setAuthenticated(boolean isAuthenticated)
			throws IllegalArgumentException {
		this.authenticated = isAuthenticated;
	}

}
