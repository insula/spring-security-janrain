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

		String xml = "<?xml version='1.0' encoding='UTF-8'?><rsp stat='ok'><profile><displayName>First Last</displayName><identifier>http://twitter.com/account/profile?user_id=12345678</identifier><name><formatted>First Last</formatted></name><photo>http://a3.twimg.com/profile_images/12345678/picture.jpg</photo><preferredUsername>username</preferredUsername><providerName>Twitter</providerName><url>http://twitter.com/edsonyanaga</url></profile></rsp>";

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

		String xml = "<?xml version='1.0' encoding='UTF-8'?><rsp stat='ok'><profile><displayName>user</displayName><email>my@email.com</email><identifier>https://www.google.com/profiles/abcdefghi12345678</identifier><name><givenName>First</givenName><familyName>Last</familyName><formatted>First Last</formatted></name><preferredUsername>user</preferredUsername><providerName>Google</providerName><url>https://www.google.com/profiles/abcdefghi12345678</url><verifiedEmail>my@email.com</verifiedEmail><googleUserId>abcdefghi12345678</googleUserId></profile></rsp>";

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

		String xml = "<?xml version='1.0' encoding='UTF-8'?><rsp stat='ok'><profile><address><formatted>City</formatted></address><displayName>First Last</displayName><email>my@email.com</email><gender>male</gender><identifier>http://www.facebook.com/profile.php?id=123456789</identifier><name><givenName>First</givenName><familyName>Last</familyName><formatted>First Last</formatted></name><photo>http://graph.facebook.com/123456789/picture?type=large</photo><preferredUsername>FirstLast</preferredUsername><providerName>Facebook</providerName><url>http://www.facebook.com/firstlast</url><utcOffset>-02:00</utcOffset><verifiedEmail>my@email.com</verifiedEmail><limitedData>false</limitedData></profile></rsp>";

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

		String xml = "<?xml version='1.0' encoding='UTF-8'?><rsp stat='ok'><profile><displayName>First</displayName><email>my@email.com</email><gender>male</gender><identifier>https://me.yahoo.com/a/asdfasdf_sdaklfdjiou123#1234d</identifier><name><formatted>First Last</formatted></name><photo>https://a123.e.akamai.net/sec.yimg.com/i/identity/profile_12a.png</photo><preferredUsername>First</preferredUsername><providerName>Yahoo!</providerName><utcOffset>-03:00</utcOffset><verifiedEmail>my@email.com</verifiedEmail></profile></rsp>";

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

		String xml = "<?xml version='1.0' encoding='UTF-8'?><rsp stat='ok'><profile><displayName>First</displayName><email>my@email.com</email><identifier>http://cid-abcdd123123123.spaces.live.com/</identifier><name><givenName>First</givenName><familyName>Last</familyName><formatted>First Last</formatted></name><preferredUsername>First</preferredUsername><providerName>Windows Live</providerName><url>http://cid-abcdd123123123.spaces.live.com/</url></profile></rsp>";

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

		String xml = "<?xml version='1.0' encoding='UTF-8'?><rsp stat='ok'><profile><birthday>2012-02-08</birthday><displayName>First Last</displayName><identifier>http://www.linkedin.com/profile?viewProfile=abcdefg</identifier><name><givenName>First</givenName><familyName>Last</familyName><formatted>First Last</formatted></name><phoneNumber>+55 11 1234-1234</phoneNumber><photo>http://media.linkedin.com/mpr/mprx/0_sadfasfdasfdafdqwueroijsajdflkjasklufopiqwul;kjsdlkjaoiuqwkejrlkjlksaf</photo><preferredUsername>First Last</preferredUsername><providerName>LinkedIn</providerName><url>http://www.insula.com.br</url></profile></rsp>";

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
