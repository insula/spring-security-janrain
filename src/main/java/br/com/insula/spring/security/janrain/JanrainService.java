package br.com.insula.spring.security.janrain;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.xpath.XPath;
import javax.xml.xpath.XPathExpressionException;
import javax.xml.xpath.XPathFactory;

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
import org.xml.sax.SAXException;

public class JanrainService {

	private HttpClient httpClient = new DefaultHttpClient(new ThreadSafeClientConnManager());

	private String apiKey;

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
			InputStream content = httpResponse.getEntity().getContent();
			Document document = parseContent(content);
			XPath xPath = createXPath();
			if (!getStringValue(document, xPath, "//rsp/@stat").equals("ok")) {
				return null;
			}
			String identifier = getStringValue(document, xPath, "//rsp/profile/identifier");
			String providerName = getStringValue(document, xPath, "//rsp/profile/providerName");
			String name = getStringValue(document, xPath, "//rsp/profile/name/formatted");
			String email = getStringValue(document, xPath, "//rsp/profile/email");
			String verifiedEmail = getStringValue(document, xPath, "//rsp/profile/verifiedEmail");
			return new JanrainAuthenticationToken(identifier, verifiedEmail, email, providerName, name);
		}
		catch (Exception ex) {
			throw new IllegalStateException(ex);
		}
	}

	protected Document parseContent(InputStream content) throws ParserConfigurationException, SAXException, IOException {
		DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
		dbf.setIgnoringElementContentWhitespace(true);
		DocumentBuilder db = dbf.newDocumentBuilder();
		Document doc = db.parse(content);
		return doc;
	}

	protected XPath createXPath() {
		XPathFactory xPathFactory = XPathFactory.newInstance();
		return xPathFactory.newXPath();
	}

	private String getStringValue(Document document, XPath xPath, String expression) throws XPathExpressionException {
		String value = xPath.evaluate(expression, document).trim();
		return value.isEmpty() ? null : value;
	}

	@Required
	public void setApiKey(String apiKey) {
		this.apiKey = apiKey;
	}

	public void setHttpClient(HttpClient httpClient) {
		this.httpClient = httpClient;
	}

}
