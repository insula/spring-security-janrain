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

import javax.servlet.http.HttpServletRequest;

import org.springframework.util.Assert;

public class Janrain {

	public static final String JANRAIN_URI = "/j_spring_janrain_security_check";

	private static final int HTTPS_PORT = 443;

	private static final int HTTP_PORT = 80;

	public String getTokenUrl(HttpServletRequest request, String path) {
		Assert.notNull(request, "'request' cannot be null");
		Assert.notNull(request, "'path' cannot be null");
		Assert.isTrue(path.startsWith("/"), "path must start with '/'");
		String scheme = request.getScheme();
		int serverPort = request.getServerPort();
		if (isRequestInDefaultPort(scheme, serverPort)) {
			return String.format("%s://%s%s", scheme, request.getServerName(), path);
		}
		else {
			return String.format("%s://%s:%d%s", scheme, request.getServerName(), serverPort, path);
		}
	}

	public String getTokenUrl(HttpServletRequest request) {
		return getTokenUrl(request, String.format("%s%s", request.getContextPath(), JANRAIN_URI));
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

	private boolean isRequestInDefaultPort(String scheme, int serverPort) {
		return isHttpWithDefaultPort(scheme, serverPort) || isHttpsWithDefaultPort(scheme, serverPort);
	}

	private boolean isHttpWithDefaultPort(String scheme, int serverPort) {
		return "http".equals(scheme) && serverPort == HTTP_PORT;
	}

	private boolean isHttpsWithDefaultPort(String scheme, int serverPort) {
		return "https".equals(scheme) && serverPort == HTTPS_PORT;
	}

}