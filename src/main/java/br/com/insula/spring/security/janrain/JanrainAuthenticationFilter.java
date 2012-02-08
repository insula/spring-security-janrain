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