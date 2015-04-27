package security.jwt;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.springframework.security.core.AuthenticationException;

public interface JwtAuthenticationExceptionHandler {
	void onAuthenticationException(ServletRequest req, ServletResponse res, AuthenticationException e);

}
