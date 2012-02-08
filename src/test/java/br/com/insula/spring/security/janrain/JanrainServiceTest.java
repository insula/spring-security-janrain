package br.com.insula.spring.security.janrain;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.mockito.Matchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;

import org.apache.http.HttpEntity;
import org.apache.http.HttpResponse;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpUriRequest;
import org.junit.Before;
import org.junit.Test;

public class JanrainServiceTest {

	private JanrainService janrainService;

	@Before
	public void init() {
		this.janrainService = new JanrainService();
	}

	@Test
	public void testAuthenticateAgainstTwitter() throws Exception {
		HttpClient httpClient = mock(HttpClient.class);
		HttpResponse response = mock(HttpResponse.class);
		HttpEntity httpEntity = mock(HttpEntity.class);

		String xml = "<?xml version='1.0' encoding='UTF-8'?>\n" + "<rsp stat='ok'>\n" + "  <profile>\n"
				+ "    <displayName>\n" + "      First Last\n" + "    </displayName>\n" + "    <identifier>\n"
				+ "      http://twitter.com/account/profile?user_id=12345678\n" + "    </identifier>\n"
				+ "    <name>\n" + "      <formatted>\n" + "        First Last\n" + "      </formatted>\n"
				+ "    </name>\n" + "    <photo>\n" + "      http://a3.twimg.com/profile_images/12345678/picture.jpg\n"
				+ "    </photo>\n" + "    <preferredUsername>\n" + "      username\n" + "    </preferredUsername>\n"
				+ "    <providerName>\n" + "      Twitter\n" + "    </providerName>\n" + "    <url>\n"
				+ "      http://twitter.com/edsonyanaga\n" + "    </url>\n" + "  </profile>\n" + "</rsp>";

		when(httpEntity.getContent()).thenReturn(new ByteArrayInputStream(xml.getBytes()));
		when(response.getEntity()).thenReturn(httpEntity);
		when(httpClient.execute(any(HttpUriRequest.class))).thenReturn(response);
		janrainService.setHttpClient(httpClient);
		JanrainAuthenticationToken token = janrainService.authenticate("abc");
		assertEquals("http://twitter.com/account/profile?user_id=12345678", token.getIdentifier());
		assertEquals("First Last", token.getName());
		assertEquals("Twitter", token.getProviderName());
		assertNull(token.getEmail());
	}

	@Test
	public void testAuthenticateAgainstGoogle() throws Exception {
		HttpClient httpClient = mock(HttpClient.class);
		HttpResponse response = mock(HttpResponse.class);
		HttpEntity httpEntity = mock(HttpEntity.class);

		String xml = "<?xml version='1.0' encoding='UTF-8'?>\n" + "<rsp stat='ok'>\n" + "  <profile>\n"
				+ "    <displayName>\n" + "      user\n" + "    </displayName>\n" + "    <email>\n"
				+ "      my@email.com\n" + "    </email>\n" + "    <identifier>\n"
				+ "      https://www.google.com/profiles/abcdefghi12345678\n" + "    </identifier>\n" + "    <name>\n"
				+ "      <givenName>\n" + "        First\n" + "      </givenName>\n" + "      <familyName>\n"
				+ "        Last\n" + "      </familyName>\n" + "      <formatted>\n" + "        First Last\n"
				+ "      </formatted>\n" + "    </name>\n" + "    <preferredUsername>\n" + "      user\n"
				+ "    </preferredUsername>\n" + "    <providerName>\n" + "      Google\n" + "    </providerName>\n"
				+ "    <url>\n" + "      https://www.google.com/profiles/abcdefghi12345678\n" + "    </url>\n"
				+ "    <verifiedEmail>\n" + "      my@email.com\n" + "    </verifiedEmail>\n" + "    <googleUserId>\n"
				+ "      abcdefghi12345678\n" + "    </googleUserId>\n" + "  </profile>\n" + "</rsp>";

		when(httpEntity.getContent()).thenReturn(new ByteArrayInputStream(xml.getBytes()));
		when(response.getEntity()).thenReturn(httpEntity);
		when(httpClient.execute(any(HttpUriRequest.class))).thenReturn(response);
		janrainService.setHttpClient(httpClient);
		JanrainAuthenticationToken token = janrainService.authenticate("abc");
		assertEquals("https://www.google.com/profiles/abcdefghi12345678", token.getIdentifier());
		assertEquals("First Last", token.getName());
		assertEquals("Google", token.getProviderName());
		assertEquals("my@email.com", token.getEmail());
		assertEquals("my@email.com", token.getVerifiedEmail());
	}

	@Test
	public void testAuthenticateAgainstFacebook() throws Exception {
		HttpClient httpClient = mock(HttpClient.class);
		HttpResponse response = mock(HttpResponse.class);
		HttpEntity httpEntity = mock(HttpEntity.class);

		String xml = "<?xml version='1.0' encoding='UTF-8'?>\n" + "<rsp stat='ok'>\n" + "  <profile>\n"
				+ "    <address>\n" + "      <formatted>\n" + "        City\n" + "      </formatted>\n"
				+ "    </address>\n" + "    <displayName>\n" + "      First Last\n" + "    </displayName>\n"
				+ "    <email>\n" + "      my@email.com\n" + "    </email>\n" + "    <gender>\n" + "      male\n"
				+ "    </gender>\n" + "    <identifier>\n" + "      http://www.facebook.com/profile.php?id=123456789\n"
				+ "    </identifier>\n" + "    <name>\n" + "      <givenName>\n" + "        First\n"
				+ "      </givenName>\n" + "      <familyName>\n" + "        Last\n" + "      </familyName>\n"
				+ "      <formatted>\n" + "        First Last\n" + "      </formatted>\n" + "    </name>\n"
				+ "    <photo>\n" + "      http://graph.facebook.com/123456789/picture?type=large\n" + "    </photo>\n"
				+ "    <preferredUsername>\n" + "      FirstLast\n" + "    </preferredUsername>\n"
				+ "    <providerName>\n" + "      Facebook\n" + "    </providerName>\n" + "    <url>\n"
				+ "      http://www.facebook.com/firstlast\n" + "    </url>\n" + "    <utcOffset>\n" + "      -02:00\n"
				+ "    </utcOffset>\n" + "    <verifiedEmail>\n" + "      my@email.com\n" + "    </verifiedEmail>\n"
				+ "    <limitedData>\n" + "      false\n" + "    </limitedData>\n" + "  </profile>\n" + "</rsp>";

		when(httpEntity.getContent()).thenReturn(new ByteArrayInputStream(xml.getBytes()));
		when(response.getEntity()).thenReturn(httpEntity);
		when(httpClient.execute(any(HttpUriRequest.class))).thenReturn(response);
		janrainService.setHttpClient(httpClient);
		JanrainAuthenticationToken token = janrainService.authenticate("abc");
		assertEquals("http://www.facebook.com/profile.php?id=123456789", token.getIdentifier());
		assertEquals("First Last", token.getName());
		assertEquals("Facebook", token.getProviderName());
		assertEquals("my@email.com", token.getEmail());
		assertEquals("my@email.com", token.getVerifiedEmail());
	}

	@Test
	public void testAuthenticateAgainstYahoo() throws Exception {
		HttpClient httpClient = mock(HttpClient.class);
		HttpResponse response = mock(HttpResponse.class);
		HttpEntity httpEntity = mock(HttpEntity.class);

		String xml = "<?xml version='1.0' encoding='UTF-8'?>\n" + "<rsp stat='ok'>\n" + "  <profile>\n"
				+ "    <displayName>\n" + "      First\n" + "    </displayName>\n" + "    <email>\n"
				+ "      my@email.com\n" + "    </email>\n" + "    <gender>\n" + "      male\n" + "    </gender>\n"
				+ "    <identifier>\n" + "      https://me.yahoo.com/a/asdfasdf_sdaklfdjiou123#1234d\n"
				+ "    </identifier>\n" + "    <name>\n" + "      <formatted>\n" + "        First Last\n"
				+ "      </formatted>\n" + "    </name>\n" + "    <photo>\n"
				+ "      https://a123.e.akamai.net/sec.yimg.com/i/identity/profile_12a.png\n" + "    </photo>\n"
				+ "    <preferredUsername>\n" + "      First\n" + "    </preferredUsername>\n" + "    <providerName>\n"
				+ "      Yahoo!\n" + "    </providerName>\n" + "    <utcOffset>\n" + "      -03:00\n"
				+ "    </utcOffset>\n" + "    <verifiedEmail>\n" + "      my@email.com\n" + "    </verifiedEmail>\n"
				+ "  </profile>\n" + "</rsp>";

		when(httpEntity.getContent()).thenReturn(new ByteArrayInputStream(xml.getBytes()));
		when(response.getEntity()).thenReturn(httpEntity);
		when(httpClient.execute(any(HttpUriRequest.class))).thenReturn(response);
		janrainService.setHttpClient(httpClient);
		JanrainAuthenticationToken token = janrainService.authenticate("abc");
		assertEquals("https://me.yahoo.com/a/asdfasdf_sdaklfdjiou123#1234d", token.getIdentifier());
		assertEquals("First Last", token.getName());
		assertEquals("Yahoo!", token.getProviderName());
		assertEquals("my@email.com", token.getEmail());
		assertEquals("my@email.com", token.getVerifiedEmail());
	}

	@Test
	public void testAuthenticateAgainstWindowsLive() throws Exception {
		HttpClient httpClient = mock(HttpClient.class);
		HttpResponse response = mock(HttpResponse.class);
		HttpEntity httpEntity = mock(HttpEntity.class);

		String xml = "<?xml version='1.0' encoding='UTF-8'?>\n" + "<rsp stat='ok'>\n" + "  <profile>\n"
				+ "    <displayName>\n" + "      First\n" + "    </displayName>\n" + "    <email>\n"
				+ "      my@email.com\n" + "    </email>\n" + "    <identifier>\n"
				+ "      http://cid-abcdd123123123.spaces.live.com/\n" + "    </identifier>\n" + "    <name>\n"
				+ "      <givenName>\n" + "        First\n" + "      </givenName>\n" + "      <familyName>\n"
				+ "        Last\n" + "      </familyName>\n" + "      <formatted>\n" + "        First Last\n"
				+ "      </formatted>\n" + "    </name>\n" + "    <preferredUsername>\n" + "      First\n"
				+ "    </preferredUsername>\n" + "    <providerName>\n" + "      Windows Live\n"
				+ "    </providerName>\n" + "    <url>\n" + "      http://cid-abcdd123123123.spaces.live.com/\n"
				+ "    </url>\n" + "  </profile>\n" + "</rsp>";

		when(httpEntity.getContent()).thenReturn(new ByteArrayInputStream(xml.getBytes()));
		when(response.getEntity()).thenReturn(httpEntity);
		when(httpClient.execute(any(HttpUriRequest.class))).thenReturn(response);
		janrainService.setHttpClient(httpClient);
		JanrainAuthenticationToken token = janrainService.authenticate("abc");
		assertEquals("http://cid-abcdd123123123.spaces.live.com/", token.getIdentifier());
		assertEquals("First Last", token.getName());
		assertEquals("Windows Live", token.getProviderName());
		assertEquals("my@email.com", token.getEmail());
		assertNull(token.getVerifiedEmail());
	}

	@Test
	public void testAuthenticateAgainstLinkedIn() throws Exception {
		HttpClient httpClient = mock(HttpClient.class);
		HttpResponse response = mock(HttpResponse.class);
		HttpEntity httpEntity = mock(HttpEntity.class);

		String xml = "<?xml version='1.0' encoding='UTF-8'?>\n"
				+ "<rsp stat='ok'>\n"
				+ "  <profile>\n"
				+ "    <birthday>\n"
				+ "      2012-02-08\n"
				+ "    </birthday>\n"
				+ "    <displayName>\n"
				+ "      First Last\n"
				+ "    </displayName>\n"
				+ "    <identifier>\n"
				+ "      http://www.linkedin.com/profile?viewProfile=abcdefg\n"
				+ "    </identifier>\n"
				+ "    <name>\n"
				+ "      <givenName>\n"
				+ "        First\n"
				+ "      </givenName>\n"
				+ "      <familyName>\n"
				+ "        Last\n"
				+ "      </familyName>\n"
				+ "      <formatted>\n"
				+ "        First Last\n"
				+ "      </formatted>\n"
				+ "    </name>\n"
				+ "    <phoneNumber>\n"
				+ "      +55 11 1234-1234\n"
				+ "    </phoneNumber>\n"
				+ "    <photo>\n"
				+ "      http://media.linkedin.com/mpr/mprx/0_sadfasfdasfdafdqwueroijsajdflkjasklufopiqwul;kjsdlkjaoiuqwkejrlkjlksaf\n"
				+ "    </photo>\n" + "    <preferredUsername>\n" + "      First Last\n" + "    </preferredUsername>\n"
				+ "    <providerName>\n" + "      LinkedIn\n" + "    </providerName>\n" + "    <url>\n"
				+ "      http://www.insula.com.br\n" + "    </url>\n" + "  </profile>\n" + "</rsp>";

		when(httpEntity.getContent()).thenReturn(new ByteArrayInputStream(xml.getBytes()));
		when(response.getEntity()).thenReturn(httpEntity);
		when(httpClient.execute(any(HttpUriRequest.class))).thenReturn(response);
		janrainService.setHttpClient(httpClient);
		JanrainAuthenticationToken token = janrainService.authenticate("abc");
		assertEquals("http://www.linkedin.com/profile?viewProfile=abcdefg", token.getIdentifier());
		assertEquals("First Last", token.getName());
		assertEquals("LinkedIn", token.getProviderName());
		assertNull(token.getEmail());
		assertNull(token.getVerifiedEmail());
	}

}
