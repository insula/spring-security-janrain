package br.com.insula.spring.security.janrain;

import org.springframework.beans.factory.annotation.Required;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;

public class JanrainAuthenticationProvider implements AuthenticationProvider {

	private AuthenticationUserDetailsService<JanrainAuthenticationToken> authenticationUserDetailsService;

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		if (authentication instanceof JanrainAuthenticationToken) {
			JanrainAuthenticationToken token = (JanrainAuthenticationToken) authentication;

			UserDetails userDetails = authenticationUserDetailsService.loadUserDetails(token);

			return new JanrainAuthenticationToken(userDetails, userDetails.getAuthorities(), token);
		}

		return null;
	}

	@Override
	public boolean supports(Class<? extends Object> authentication) {
		return JanrainAuthenticationToken.class.isAssignableFrom(authentication);
	}

	@Required
	public void setAuthenticationUserDetailsService(
			AuthenticationUserDetailsService<JanrainAuthenticationToken> authenticationUserDetailsService) {
		this.authenticationUserDetailsService = authenticationUserDetailsService;
	}

}