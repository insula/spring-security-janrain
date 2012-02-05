package br.com.insula.spring.security.janrain;

import java.io.UnsupportedEncodingException;

import javax.servlet.http.HttpServletRequest;

public class Janrain {

	private Janrain() {
	}

	public static String generateTokenUrl(HttpServletRequest request) throws UnsupportedEncodingException {
		if (isHttpWithDefaultPort(request) || isHttpsWithDefaultPort(request)) {
			return String.format("%s://%s%s/j_spring_janrain_security_check", request.getScheme(),
					request.getServerName(), request.getContextPath());
		}
		return String.format("%s://%s:%d%s/j_spring_janrain_security_check", request.getScheme(),
				request.getServerName(), request.getServerPort(), request.getContextPath());
	}

	private static boolean isHttpWithDefaultPort(HttpServletRequest request) {
		return "http".equals(request.getScheme()) && request.getServerPort() == 80;
	}

	private static boolean isHttpsWithDefaultPort(HttpServletRequest request) {
		return "https".equals(request.getScheme()) && request.getServerPort() == 443;
	}

}