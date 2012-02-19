package br.com.insula.spring.security.janrain;

import static org.junit.Assert.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.UnsupportedEncodingException;

import javax.servlet.http.HttpServletRequest;

import org.junit.Before;
import org.junit.Test;

public class JanrainTest {

	private static final String REQUEST_URI = "/insula/mapping?queryString=1e1";

	private Janrain janrain;

	@Before
	public void init() {
		this.janrain = new Janrain();
	}

	@Test
	public void testGetTokenUrlHttpServletRequestString() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getServerName()).thenReturn("localhost");
		when(request.getContextPath()).thenReturn("/janrain");
		when(request.getScheme()).thenReturn("http", "http", "https", "https");
		when(request.getServerPort()).thenReturn(80, 8080, 443, 8443);
		assertEquals("http://localhost/insula/mapping?queryString=1e1", janrain.getTokenUrl(request, REQUEST_URI));
		assertEquals("http://localhost:8080/insula/mapping?queryString=1e1", janrain.getTokenUrl(request, REQUEST_URI));
		assertEquals("https://localhost/insula/mapping?queryString=1e1", janrain.getTokenUrl(request, REQUEST_URI));
		assertEquals("https://localhost:8443/insula/mapping?queryString=1e1", janrain.getTokenUrl(request, REQUEST_URI));
	}

	@Test
	public void testGetTokenUrlHttpServletRequest() throws UnsupportedEncodingException {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.getServerName()).thenReturn("localhost");
		when(request.getContextPath()).thenReturn("/janrain");
		when(request.getScheme()).thenReturn("http", "http", "https", "https");
		when(request.getServerPort()).thenReturn(80, 8080, 443, 8443);
		assertEquals("http://localhost/janrain/j_spring_janrain_security_check", janrain.getTokenUrl(request));
		assertEquals("http://localhost:8080/janrain/j_spring_janrain_security_check", janrain.getTokenUrl(request));
		assertEquals("https://localhost/janrain/j_spring_janrain_security_check", janrain.getTokenUrl(request));
		assertEquals("https://localhost:8443/janrain/j_spring_janrain_security_check", janrain.getTokenUrl(request));
	}

	@Test
	public void testGetEngageJsUrl() {
		HttpServletRequest request = mock(HttpServletRequest.class);
		when(request.isSecure()).thenReturn(false, true);
		assertEquals("http://widget-cdn.rpxnow.com/js/lib/insula/engage.js", janrain.getEngageJsUrl(request, "insula"));
		assertEquals("https://rpxnow.com/js/lib/insula/engage.js", janrain.getEngageJsUrl(request, "insula"));
	}

}