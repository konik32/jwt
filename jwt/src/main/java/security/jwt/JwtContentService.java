package security.jwt;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public interface JwtContentService {

	JwtContent getJwtContent(String login, String password) throws BadCredentialsException, UsernameNotFoundException;
}
