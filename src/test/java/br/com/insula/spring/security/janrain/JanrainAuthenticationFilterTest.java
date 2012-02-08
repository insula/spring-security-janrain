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