/*
 *  (C) Copyright 2012 Insula Tecnologia da Informacao Ltda.
 *
 *  This file is part of spring-security-janrain.
 *
 *  spring-security-janrain is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU Lesser General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  spring-security-janrain is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public License
 *  along with spring-security-janrain.  If not, see <http://www.gnu.org/licenses/>.
 */
package br.com.insula.spring.security.janrain;

import org.springframework.beans.factory.annotation.Required;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.core.userdetails.UserDetails;

public class JanrainAuthenticationProvider implements AuthenticationProvider {

	private AuthenticationUserDetailsService<JanrainAuthenticationToken> authenticationUserDetailsService;

	@Override
	public Authentication authenticate(Authentication authentication) {
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