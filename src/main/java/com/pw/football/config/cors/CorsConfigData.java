package com.pw.football.config.cors;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;

import java.util.List;

@ConfigurationProperties(prefix = "cors")
@ConstructorBinding
public record CorsConfigData(List<String> origins, List<String> methods,
                             List<String> headers) {
}