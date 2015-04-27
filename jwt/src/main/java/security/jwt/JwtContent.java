package security.jwt;

import java.io.Serializable;
import java.util.Collection;

import org.springframework.security.core.GrantedAuthority;


public interface JwtContent extends Serializable {

	
	Long getExpires();
	String getName();
	Collection<? extends GrantedAuthority> getAuthorities();
	void setExpires(Long expires);
}
