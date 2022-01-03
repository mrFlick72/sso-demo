package com.example.ssodemo;

import it.valeriovaudi.vauthenticator.security.clientsecuritystarter.session.management.OAuth2AuthorizationRequestResolverWithSessionState;
import it.valeriovaudi.vauthenticator.security.clientsecuritystarter.user.VAuthenticatorOAuth2User;
import it.valeriovaudi.vauthenticator.security.clientsecuritystarter.user.VAuthenticatorOidcUserService;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.CustomUserTypesOAuth2UserService;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;
import java.util.Map;

@SpringBootApplication
public class SsoDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SsoDemoApplication.class, args);
    }

}

@RestController
class HelloController {

    @GetMapping("/hello")
    public String hello() {
        return "hello";
    }

    @GetMapping("/principal")
    public Principal principal(Principal principal) {
        return principal;
    }
}


@EnableWebSecurity
class OAuth2SecurityConfig extends WebSecurityConfigurerAdapter {

    private final String postLogoutRedirectUri;
    private final ClientRegistrationRepository clientRegistrationRepository;
    private final OAuth2AuthorizationRequestResolverWithSessionState oAuth2AuthorizationRequestResolverWithSessionState;

    public OAuth2SecurityConfig(@Value("${postLogoutRedirectUri}") String postLogoutRedirectUri,
                                ClientRegistrationRepository clientRegistrationRepository,
                                OAuth2AuthorizationRequestResolverWithSessionState oAuth2AuthorizationRequestResolverWithSessionState) {
        this.postLogoutRedirectUri = postLogoutRedirectUri;
        this.clientRegistrationRepository = clientRegistrationRepository;
        this.oAuth2AuthorizationRequestResolverWithSessionState = oAuth2AuthorizationRequestResolverWithSessionState;
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
        OidcClientInitiatedLogoutSuccessHandler logoutSuccessHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
        logoutSuccessHandler.setPostLogoutRedirectUri(postLogoutRedirectUri);
        http.csrf().disable().headers().frameOptions().disable().and()
                .authorizeRequests().anyRequest().authenticated()
                .and().logout()
                .logoutSuccessHandler(logoutSuccessHandler)
                .and().oauth2Login()
                .userInfoEndpoint().oidcUserService(vAuthenticatorOidcUserService())
                .and()
                .authorizationEndpoint().authorizationRequestResolver(oAuth2AuthorizationRequestResolverWithSessionState);
    }

    public VAuthenticatorOidcUserService vAuthenticatorOidcUserService() {
        return new VAuthenticatorOidcUserService(new OidcUserService(),
                new CustomUserTypesOAuth2UserService(Map.of("client", VAuthenticatorOAuth2User.class))
        );
    }
}