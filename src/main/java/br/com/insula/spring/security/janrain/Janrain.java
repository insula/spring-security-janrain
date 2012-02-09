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

import java.io.UnsupportedEncodingException;

import javax.servlet.http.HttpServletRequest;

import org.springframework.util.Assert;

public class Janrain {

	private static final int HTTPS_PORT = 443;

	private static final int HTTP_PORT = 80;

	public String getTokenUrl(HttpServletRequest request, String path) throws UnsupportedEncodingException {
		Assert.notNull(request, "'request' cannot be null");
		Assert.notNull(request, "'path' cannot be null");
		if (isHttpWithDefaultPort(request) || isHttpsWithDefaultPort(request)) {
			return String.format("%s://%s%s/%s", request.getScheme(), request.getServerName(),
					request.getContextPath(), path);
		}
		else {
			return String.format("%s://%s:%d%s/%s", request.getScheme(), request.getServerName(),
					request.getServerPort(), request.getContextPath(), path);
		}
	}

	public String getTokenUrl(HttpServletRequest request) throws UnsupportedEncodingException {
		Assert.notNull(request, "'request' cannot be null");
		if (isHttpWithDefaultPort(request) || isHttpsWithDefaultPort(request)) {
			return String.format("%s://%s%s/j_spring_janrain_security_check", request.getScheme(),
					request.getServerName(), request.getContextPath());
		}
		else {
			return String.format("%s://%s:%d%s/j_spring_janrain_security_check", request.getScheme(),
					request.getServerName(), request.getServerPort(), request.getContextPath());
		}
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
		return "http".equals(request.getScheme()) && request.getServerPort() == HTTP_PORT;
	}

	private boolean isHttpsWithDefaultPort(HttpServletRequest request) {
		return "https".equals(request.getScheme()) && request.getServerPort() == HTTPS_PORT;
	}

}