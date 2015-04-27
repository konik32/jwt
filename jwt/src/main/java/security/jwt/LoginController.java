package security.jwt;

import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import javax.validation.constraints.NotNull;

import lombok.Data;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

@Controller
public class LoginController {

	private static final String LOGIN_URL = "/security/login";

	@Autowired
	private JwtContentService jwtContentService;

	@Autowired
	private TokenAuthenticationService tokenAuthenticationService;

	@RequestMapping(value = LOGIN_URL, method = RequestMethod.POST, consumes = "application/json")
	public void login(@RequestBody @Valid LoginDto loginDto, final HttpServletResponse response) {
		final JwtContent jwtContent = jwtContentService.getJwtContent(loginDto.getLogin(), loginDto.getPassword());
		tokenAuthenticationService.addAuthentication(response, jwtContent);
	}

	@Data
	public static class LoginDto {
		@NotNull
		private String login;
		@NotNull
		private String password;
	}
}
