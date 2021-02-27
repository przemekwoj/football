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

    @GetMapping("oauth2/token")
    public Test token(@RequestParam String code) throws URISyntaxException {
        System.out.println("oauth2/token");
        String url = "https://oauth2.googleapis.com/token";
        RestTemplate restTemplate = new RestTemplate();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        URI uri = new URI(url);
        String body = "code=" + code + "&client_id=747889372962-a1ifq94741pv37g3fad1ndo28ve224di.apps.googleusercontent.com&client_secret=YIx9dtLzBY6Z_98T1CEsaYQQ&redirect_uri=http://localhost:4200/callback&grant_type=authorization_code";
        var entity = new HttpEntity<>(body, headers);

        ResponseEntity<String> result = restTemplate.postForEntity(uri, entity, String.class);
        String resultInString = result.getBody();
        String[] arrayResult = resultInString.split("\"");
        return new Test(arrayResult[3], arrayResult[3]);
    }

    @GetMapping("/oidc-principal")
    public OidcUser getOidcUserPrincipal(
            @AuthenticationPrincipal OidcUser principal) {
        return principal;
    }

    @GetMapping("/home")
    public Test home() {
        System.out.println("Home");
        return new Test("home", "home");
    }

//    @GetMapping("login")
//    public String login() {
//        System.out.println("test2");
//        return "login";
//    }


//    @RequestMapping("/resource")
//    public Map<String, Object> home() {
//        var model = new HashMap<String, Object>();
//        model.put("id", UUID.randomUUID().toString());
//        model.put("content", "Hello World");
//        return model;
//    }
}
