package security.jwt;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.util.Assert;


public class TokenAuthenticationService {

	public static final String AUTH_HEADER_NAME = "X-AUTH-TOKEN";
	public static final String AUTH_COOKIE_NAME = "AUTH-TOKEN";
	@Autowired
	private TokenHandler tokenHandler;

	private Long expires;
	private final Class<? extends JwtContent> jwtContentType;

	public TokenAuthenticationService(Long expires, Class<? extends JwtContent> jwtContentType) {
		Assert.notNull(expires);
		Assert.notNull(jwtContentType);
		this.expires = expires;
		this.jwtContentType = jwtContentType;
	}

	public void addAuthentication(HttpServletResponse response, JwtContent jwtContent) {
		response.addHeader(AUTH_HEADER_NAME, getToken(jwtContent));
	}

	public void addCookieAuthentication(HttpServletResponse response, JwtContent jwtContent) {
		response.addCookie(createCookieForToken(getToken(jwtContent)));
	}
	
	private Cookie createCookieForToken(String token) {
		final Cookie authCookie = new Cookie(AUTH_COOKIE_NAME, token);
		authCookie.setPath("/");
		return authCookie;
	}

	private String getToken(JwtContent jwtContent) {
		jwtContent.setExpires(System.currentTimeMillis() + expires);
		return tokenHandler.createTokenForJwtContent(jwtContent);
	}

	public Authentication getAuthentication(HttpServletRequest request) {
		final String token = request.getHeader(AUTH_HEADER_NAME);
		if (token != null) {
			final JwtContent jwtContent = tokenHandler.parseJwtContentFromToken(token, jwtContentType);
			return new JwtContentAuthentication(jwtContent);
		}
		return null;
	}
}
