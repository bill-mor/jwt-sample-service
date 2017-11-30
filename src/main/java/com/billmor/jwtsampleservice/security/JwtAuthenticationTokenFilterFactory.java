package com.billmor.jwtsampleservice.security;

import com.billmor.jwtsampleservice.service.JwtTokenService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class JwtAuthenticationTokenFilterFactory {

    private final JwtTokenService jwtTokenService;
    private final String tokenHeader;

    @Autowired
    public JwtAuthenticationTokenFilterFactory(JwtTokenService jwtTokenService, @Value("${jwt.header}") String tokenHeader) {
        this.jwtTokenService = jwtTokenService;
        this.tokenHeader = tokenHeader;
    }

    public JwtAuthenticationTokenFilter build(){
        return new JwtAuthenticationTokenFilter(jwtTokenService, tokenHeader);
    }
}
