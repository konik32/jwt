package security.jwt;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.util.Assert;
import org.springframework.web.filter.GenericFilterBean;

public class JwtAuthenticationFilter extends GenericFilterBean {

	private final TokenAuthenticationService tokenAuthenticationService;
	private JwtAuthenticationExceptionHandler exceptionHadler;

	public JwtAuthenticationFilter(TokenAuthenticationService taService) {
		Assert.notNull(taService);
		this.tokenAuthenticationService = taService;
	}

	@Override
	public void doFilter(ServletRequest req, ServletResponse res, FilterChain chain) throws IOException,
			ServletException {
		try {
			Authentication auth = tokenAuthenticationService.getAuthentication((HttpServletRequest) req);
			if (auth != null)
				SecurityContextHolder.getContext().setAuthentication(auth);
			chain.doFilter(req, res);
		} catch (AuthenticationException ex) {
			if (exceptionHadler != null)
				exceptionHadler.onAuthenticationException(req, res, ex);
		}

	}

	public void setExceptionHadler(JwtAuthenticationExceptionHandler exceptionHadler) {
		this.exceptionHadler = exceptionHadler;
	}
}
