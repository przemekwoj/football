package com.pw.football.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.HttpStatusReturningLogoutSuccessHandler;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Collections;

@Configuration
@EnableWebSecurity
public class OAuth2LoginSecurityConfig
        extends WebSecurityConfigurerAdapter {

    private final ObjectMapper mapper;
    private final TokenStore tokenStore;
    private final TokenFilter tokenFilter;

    public OAuth2LoginSecurityConfig(ObjectMapper mapper, TokenStore tokenStore,
                                     TokenFilter tokenFilter) {
        this.mapper = mapper;
        this.tokenStore = tokenStore;
        this.tokenFilter = tokenFilter;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        http
                .cors()
                .and()
                .authorizeRequests()
                .antMatchers("/oauth2/**", "/login**", "/logout").permitAll()
                .anyRequest().authenticated()
                .and()
                .oauth2Login()
                .authorizationEndpoint()
                .authorizationRequestRepository(new InMemoryRequestRepository())
                .and()
                .successHandler(this::successHandler)
                .and()
                .logout(cust ->
                        cust.addLogoutHandler(this::logout).logoutSuccessHandler(this::onLogoutSuccess)
                )
                .csrf().disable();

        http.addFilterBefore(tokenFilter, UsernamePasswordAuthenticationFilter.class);

    }


    //
//                .and()
//                .logout()
//                .logoutUrl("/user/logout")
//                .addLogoutHandler(logoutHandler)
//                .logoutSuccessHandler(new HttpStatusReturningLogoutSuccessHandler(HttpStatus.OK))
//                .permitAll();
//        http.logout().permitAll().logoutSuccessUrl("http://localhost:4200/login");
//        http.logout().logoutSuccessHandler((new HttpStatusReturningLogoutSuccessHandler(HttpStatus.OK)));

    private void logout(HttpServletRequest request, HttpServletResponse response,
                        Authentication authentication) {
        // You can process token here
        System.out.println("HERE123");
        System.out.println("Auth token is - " + request.getHeader("Authorization"));
    }

    void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                         Authentication authentication) throws IOException, ServletException {
        // this code is just sending the 200 ok response and preventing redirect
        System.out.println("HERE6767");
        response.setStatus(HttpServletResponse.SC_OK);
    }

    private void successHandler(HttpServletRequest request,
                                HttpServletResponse response, Authentication authentication) throws IOException {
        String token = tokenStore.generateToken(authentication);
        response.getWriter().write(
                mapper.writeValueAsString(Collections.singletonMap("accessToken", token))
        );
    }

    private void authenticationEntryPoint(HttpServletRequest request, HttpServletResponse response,
                                          AuthenticationException authException) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.getWriter().write(mapper.writeValueAsString(Collections.singletonMap("error", "Unauthenticated")));
    }

    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowedMethods(Collections.singletonList("*"));
        config.setAllowedOrigins(Collections.singletonList("http://localhost:4200"));
        config.setAllowedHeaders(Collections.singletonList("*"));

        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }
}