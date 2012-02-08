package br.com.insula.spring.security.janrain;

import java.io.UnsupportedEncodingException;

import javax.servlet.http.HttpServletRequest;

import org.springframework.util.Assert;

public class Janrain {

	public String getTokenUrl(HttpServletRequest request, String path) throws UnsupportedEncodingException {
		Assert.notNull(request, "'request' cannot be null");
		Assert.notNull(request, "'path' cannot be null");
		if (isHttpWithDefaultPort(request) || isHttpsWithDefaultPort(request)) {
			return String.format("%s://%s%s/%s", request.getScheme(), request.getServerName(),
					request.getContextPath(), path);
		}
		return String.format("%s://%s:%d%s/%s", request.getScheme(), request.getServerName(), request.getServerPort(),
				request.getContextPath());
	}

	public String getTokenUrl(HttpServletRequest request) throws UnsupportedEncodingException {
		Assert.notNull(request, "'request' cannot be null");
		if (isHttpWithDefaultPort(request) || isHttpsWithDefaultPort(request)) {
			return String.format("%s://%s%s/j_spring_janrain_security_check", request.getScheme(),
					request.getServerName(), request.getContextPath());
		}
		return String.format("%s://%s:%d%s/j_spring_janrain_security_check", request.getScheme(),
				request.getServerName(), request.getServerPort(), request.getContextPath());
	}

	public String getEngageJsUrl(HttpServletRequest request, String applicationName) {
		Assert.notNull(request, "'request' cannot be null");
		if (request.isSecure()) {
			return String.format("https://rpxnow.com/js/lib/%s/engage.js", applicationName);
		}
		else {
			return String.format("http://widget-cdn.rpxnow.com/js/lib/%s/engage.js", applicationName);
		}
	}

	private boolean isHttpWithDefaultPort(HttpServletRequest request) {
		return "http".equals(request.getScheme()) && request.getServerPort() == 80;
	}

	private boolean isHttpsWithDefaultPort(HttpServletRequest request) {
		return "https".equals(request.getScheme()) && request.getServerPort() == 443;
	}

}