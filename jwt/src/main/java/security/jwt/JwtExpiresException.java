package security.jwt;

import org.springframework.security.core.AuthenticationException;

public class JwtExpiresException extends AuthenticationException {

	
	public JwtExpiresException() {
		super("Jwt expired");
	}

	private static final long serialVersionUID = -7495322631999926800L;

}
