package security.jwt;

import org.springframework.security.core.AuthenticationException;

public class JwtWrongFormatException extends AuthenticationException  {

	public JwtWrongFormatException(String msg, Throwable t) {
		super(msg, t);
	}
	
	public JwtWrongFormatException() {
		super("Jwt has wrong format");
	}
	/**
	 * 
	 */
	private static final long serialVersionUID = -6481959560643204844L;

}
