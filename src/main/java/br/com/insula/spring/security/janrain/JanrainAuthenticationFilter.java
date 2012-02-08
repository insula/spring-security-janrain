package br.com.insula.spring.security.janrain;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Required;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;

public class JanrainAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	private JanrainService janrainService;

	protected JanrainAuthenticationFilter() {
		super("/j_spring_janrain_security_check");
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {
		String token = request.getParameter("token");

		if (token != null && !token.isEmpty()) {
			JanrainAuthenticationToken authentication = janrainService.authenticate(token);
			if (authentication != null) {
				return getAuthenticationManager().authenticate(authentication);
			}
			else {
				throw new AuthenticationServiceException(
						"Unable to parse authentication. Is your 'applicationName' correct?");
			}
		}

		return null;
	}

	@Required
	public void setJanrainService(JanrainService janrainService) {
		this.janrainService = janrainService;
	}

}