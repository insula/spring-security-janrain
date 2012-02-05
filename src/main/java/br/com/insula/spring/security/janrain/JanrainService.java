package br.com.insula.spring.security.janrain;


import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import org.apache.http.HttpResponse;
import org.apache.http.NameValuePair;
import org.apache.http.client.HttpClient;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.DefaultHttpClient;
import org.apache.http.impl.conn.tsccm.ThreadSafeClientConnManager;
import org.apache.http.message.BasicNameValuePair;
import org.springframework.beans.factory.annotation.Required;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

public class JanrainService {

	private HttpClient httpClient;

	private String apiKey;

	public JanrainService() {
		this.httpClient = new DefaultHttpClient(new ThreadSafeClientConnManager());
	}

	public JanrainAuthenticationToken authenticate(String token) throws IOException {
		HttpPost httpPost = new HttpPost("https://rpxnow.com/api/v2/auth_info");
		List<NameValuePair> params = new ArrayList<NameValuePair>();
		params.add(new BasicNameValuePair("format", "xml"));
		params.add(new BasicNameValuePair("apiKey", apiKey));
		params.add(new BasicNameValuePair("token", token));
		UrlEncodedFormEntity entity = new UrlEncodedFormEntity(params, "UTF-8");
		httpPost.setEntity(entity);
		HttpResponse httpResponse = httpClient.execute(httpPost);

		try {
			DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
			dbf.setIgnoringElementContentWhitespace(true);
			DocumentBuilder db = dbf.newDocumentBuilder();
			Document doc = db.parse(httpResponse.getEntity().getContent());
			Element response = doc.getDocumentElement();
			if (!response.getAttribute("stat").equals("ok")) {
				throw new IllegalArgumentException("Unexpected API error");
			}
			String email = response.getElementsByTagName("verifiedEmail").item(0).getTextContent();
			String identifier = response.getElementsByTagName("identifier").item(0).getTextContent();
			String name = response.getElementsByTagName("formatted").item(0).getTextContent();
			String providerName = response.getElementsByTagName("providerName").item(0).getTextContent();
			return new JanrainAuthenticationToken(identifier, email, providerName, name);
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}

	}

	@Required
	public void setApiKey(String apiKey) {
		this.apiKey = apiKey;
	}

	public void setHttpClient(HttpClient httpClient) {
		this.httpClient = httpClient;
	}

}
