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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.mockito.Mockito.RETURNS_MOCKS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.junit.Before;
import org.junit.Test;
import org.springframework.security.authentication.AuthenticationManager;

public class JanrainAuthenticationFilterTest {

	private JanrainAuthenticationFilter filter;

	@Before
	public void init() {
		this.filter = new JanrainAuthenticationFilter();
	}

	@Test
	public void testAttemptAuthenticationWithoutToken() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		HttpServletResponse response = mock(HttpServletResponse.class);
		assertNull(filter.attemptAuthentication(request, response));
	}

	@Test
	public void testAttemptAuthenticationWithToken() throws Exception {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getParameter("token")).thenReturn("abcdefg");
		HttpServletResponse response = mock(HttpServletResponse.class);
		JanrainService janrainService = mock(JanrainService.class, RETURNS_MOCKS);
		AuthenticationManager authenticationManager = mock(AuthenticationManager.class, RETURNS_MOCKS);
		filter.setAuthenticationManager(authenticationManager);
		filter.setJanrainService(janrainService);
		assertNotNull(filter.attemptAuthentication(request, response));
	}

}