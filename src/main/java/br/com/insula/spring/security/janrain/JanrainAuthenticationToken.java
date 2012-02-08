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