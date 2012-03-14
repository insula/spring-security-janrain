package br.com.insula.spring.security.janrain;

public class JanrainException extends RuntimeException {

	private static final long serialVersionUID = 1L;

	public JanrainException(String message) {
		super(message);
	}

	public JanrainException(String message, Throwable cause) {
		super(message, cause);
	}

}