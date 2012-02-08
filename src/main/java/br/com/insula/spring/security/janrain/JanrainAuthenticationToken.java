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

import java.util.Collection;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;

public class JanrainAuthenticationToken extends AbstractAuthenticationToken {

	private static final long serialVersionUID = 1L;

	private final Object principal;

	private final String identifier;

	private final String verifiedEmail;

	private final String email;

	private final String providerName;

	private final String name;

	public JanrainAuthenticationToken(String identifier, String verifiedEmail, String email, String providerName,
			String name) {
		super(AuthorityUtils.NO_AUTHORITIES);
		this.principal = null;
		this.identifier = identifier;
		this.verifiedEmail = verifiedEmail;
		this.email = email;
		this.providerName = providerName;
		this.name = name;
	}

	public JanrainAuthenticationToken(Object principal, Collection<? extends GrantedAuthority> authorities,
			JanrainAuthenticationToken token) {
		super(authorities);
		this.principal = principal;
		this.identifier = token.identifier;
		this.verifiedEmail = token.verifiedEmail;
		this.email = token.email;
		this.providerName = token.providerName;
		this.name = token.name;
	}

	@Override
	public Object getCredentials() {
		return null;
	}

	@Override
	public Object getPrincipal() {
		return principal;
	}

	public String getIdentifier() {
		return identifier;
	}

	public String getVerifiedEmail() {
		return verifiedEmail;
	}

	public String getEmail() {
		return email;
	}

	public String getProviderName() {
		return providerName;
	}

	public String getName() {
		return name;
	}

}