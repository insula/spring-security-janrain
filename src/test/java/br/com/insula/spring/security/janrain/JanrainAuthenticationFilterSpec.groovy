package br.com.insula.spring.security.janrain

import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import org.springframework.security.authentication.AuthenticationManager
import org.springframework.security.core.Authentication
import spock.lang.Specification

class JanrainAuthenticationFilterSpec extends Specification {

    def filter = new JanrainAuthenticationFilter()

    def "should not authenticate without the token"() {
        expect:
        null == filter.attemptAuthentication(Mock(HttpServletRequest), Mock(HttpServletResponse))
    }

    def "should authenticate with a valid token"() {
        given:
        janrainAcceptsToken 'abcdefg'
        def request = aRequestWithParams token:'abcdefg'

        expect:
        filter.attemptAuthentication(request, Mock(HttpServletResponse)) != null
    }
    
    private HttpServletRequest aRequestWithParams(parameters) {
        def request = Mock(HttpServletRequest)
        
        parameters.each {k,v ->
            request.getParameter(k) >> v
        }
        
        request
    }
    
    private void janrainAcceptsToken(String validToken) {
        def janrainService = Mock(JanrainService)
        def authenticationManager = Mock(AuthenticationManager)
        def authenticationToken = Mock(JanrainAuthenticationToken)
        
        janrainService.authenticate(validToken) >> authenticationToken
        authenticationManager.authenticate(authenticationToken) >> Mock(Authentication)
        
        filter.janrainService = janrainService
        filter.authenticationManager = authenticationManager
    }

}
