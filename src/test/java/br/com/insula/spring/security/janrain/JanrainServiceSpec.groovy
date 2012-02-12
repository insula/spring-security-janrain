package br.com.insula.spring.security.janrain

import groovy.xml.MarkupBuilder
import org.apache.http.HttpEntity
import org.apache.http.HttpResponse
import org.apache.http.client.HttpClient
import spock.lang.Specification

class JanrainServiceSpec extends Specification {

    def janrainService = new JanrainService()

    def "should authenticate against Twitter"() {
        given:
        providerWillRespond { xml ->
            xml.rsp(stat: 'ok') {
                profile {
                    displayName 'First Last'
                    identifier 'http://twitter.com/account/profile?user_id=12345678'
                    name {
                        formatted 'First Last'
                    }
                    photo 'http://a3.twimg.com/profile_images/12345678/picture.jpg'
                    preferredUsername 'username'
                    providerName 'Twitter'
                    url 'http://twitter.com/edsonyanaga'
                }
            }
        }

        when:
        def token = janrainService.authenticate('abc')

        then:
        token.identifier == 'http://twitter.com/account/profile?user_id=12345678'
        token.name == "First Last"
        token.providerName == "Twitter"
        !token.email
    }


    def "should authenticate against Google"() {
        given:
        providerWillRespond { xml ->
            xml.rsp(stat: 'ok') {
                profile {
                    displayName 'user'
                    email 'my@email.com'
                    identifier 'https://www.google.com/profiles/abcdefghi12345678'
                    name {
                        givenName 'First'
                        familyName 'Last'
                        formatted 'First Last'
                    }
                    preferredUsername 'user'
                    providerName 'Google'
                    url 'https://www.google.com/profiles/abcdefghi12345678'
                    verifiedEmail 'my@email.com'
                    googleUserId 'abcdefghi12345678'
                }
            }
        }

        when:
        def token = janrainService.authenticate('abc')

        then:
        token.identifier == 'https://www.google.com/profiles/abcdefghi12345678'
        token.name == "First Last"
        token.providerName == "Google"
        token.email == 'my@email.com'
        token.verifiedEmail == 'my@email.com'
    }

    def "should authenticate against Facebook"() {
        given:
        providerWillRespond { xml ->
            xml.rsp(stat: 'ok') {
                profile {
                    address {
                        formatted 'City'
                    }
                    displayName 'First Last'
                    email 'my@email.com'
                    gender 'male'
                    identifier 'http://www.facebook.com/profile.php?id=123456789'
                    name {
                        givenName 'First'
                        familyName 'Last'
                        formatted 'First Last'
                    }
                    photo 'http://graph.facebook.com/123456789/picture?type=large'
                    preferredUsername 'FirstLast'
                    providerName 'Facebook'
                    url 'http://www.facebook.com/firstlast'
                    utcOffset '-02:00'
                    verifiedEmail 'my@email.com'
                    limitedData 'false'
                }
            }
        }

        when:
        def token = janrainService.authenticate('abc')

        then:
        token.identifier == 'http://www.facebook.com/profile.php?id=123456789'
        token.name == "First Last"
        token.providerName == "Facebook"
        token.email == 'my@email.com'
        token.verifiedEmail == 'my@email.com'
    }

    def "should authenticate against Yahoo!"() {
        given:
        providerWillRespond { xml ->
            xml.rsp(stat: 'ok') {
                profile {
                    displayName 'First'
                    email 'my@email.com'
                    gender 'male'
                    identifier 'https://me.yahoo.com/a/asdfasdf_sdaklfdjiou123#1234d'
                    name {
                        formatted 'First Last'
                    }
                    photo 'http://graph.facebook.com/123456789/picture?type=large'
                    preferredUsername 'First'
                    providerName 'Yahoo!'
                    utcOffset '-03:00'
                    verifiedEmail 'my@email.com'
                }
            }
        }

        when:
        def token = janrainService.authenticate('abc')

        then:
        token.identifier == 'https://me.yahoo.com/a/asdfasdf_sdaklfdjiou123#1234d'
        token.name == "First Last"
        token.providerName == "Yahoo!"
        token.email == 'my@email.com'
        token.verifiedEmail == 'my@email.com'
    }

    def "should authenticate against Windows Live"() {
        given:
        providerWillRespond { xml ->
            xml.rsp(stat: 'ok') {
                profile {
                    displayName 'First'
                    email 'my@email.com'
                    identifier 'http://cid-abcdd123123123.spaces.live.com/'
                    name {
                        givenName 'First'
                        familyName 'Last'
                        formatted 'First Last'
                    }
                    preferredUsername 'First'
                    providerName 'Windows Live'
                    url 'http://cid-abcdd123123123.spaces.live.com/'
                }
            }
        }

        when:
        def token = janrainService.authenticate('abc')

        then:
        token.identifier == 'http://cid-abcdd123123123.spaces.live.com/'
        token.name == "First Last"
        token.providerName == "Windows Live"
        token.email == 'my@email.com'
        !token.verifiedEmail
    }

    def "should authenticate against LinkedIn"() {
        given:
        providerWillRespond { xml ->
            xml.rsp(stat: 'ok') {
                profile {
                    birthday '2012-02-08'
                    displayName 'First Last'
                    identifier 'http://www.linkedin.com/profile?viewProfile=abcdefg'
                    name {
                        givenName 'First'
                        familyName 'Last'
                        formatted 'First Last'
                    }
                    phoneNumber '55 11 1234-1234'
                    photo 'http://media.linkedin.com/mpr/mprx/0_sadfasfdasfdafdqwueroijsajdflkjasklufopiqwul;kjsdlkjaoiuqwkejrlkjlksaf'
                    preferredUsername 'First Last'
                    providerName 'LinkedIn'
                    url 'http://www.insula.com.br'
                }
            }
        }

        when:
        def token = janrainService.authenticate('abc')

        then:
        token.identifier == 'http://www.linkedin.com/profile?viewProfile=abcdefg'
        token.name == "First Last"
        token.providerName == "LinkedIn"
        !token.email
        !token.verifiedEmail
    }

    private void providerWillRespond(Closure xmlCallback) {
        def xmlOutput = new StringWriter()
        def xmlBuilder = new MarkupBuilder(xmlOutput)
        xmlCallback(xmlBuilder)

        def httpClient = Mock(HttpClient)
        def response = Mock(HttpResponse)
        def httpEntity = Mock(HttpEntity)

        httpEntity.getContent() >> new ByteArrayInputStream(xmlOutput.toString().bytes)
        response.getEntity() >> httpEntity
        httpClient.execute(_) >> response

        janrainService.httpClient = httpClient
    }

}
