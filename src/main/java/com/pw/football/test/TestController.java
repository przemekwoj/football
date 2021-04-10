package com.pw.football.test;

import com.pw.football.config.TokenFilter;
import com.pw.football.config.TokenStore;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

@RestController
public class TestController {
    private final TokenStore tokenStore;
    private final TokenFilter tokenFilter;

    public TestController(TokenStore tokenStore,
                          TokenFilter tokenFilter) {
        this.tokenStore = tokenStore;
        this.tokenFilter = tokenFilter;
    }

    @GetMapping("test")
    public Test test() {
        System.out.println("test2");
        return new Test("imie", "naziwsko");
    }

    @GetMapping("/home")
    public Test home() {
        System.out.println("Home");
        return new Test("home", "home");
    }

    @GetMapping("/home2")
    public Test home2() {
        System.out.println("Home2");
        return new Test("home2", "home2");
    }

}
