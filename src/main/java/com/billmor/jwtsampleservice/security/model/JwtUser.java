package com.billmor.jwtsampleservice.security.model;

import lombok.Builder;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Date;

@Data
@Builder
public class JwtUser  {
    private final String username;
    private final String issuer;
    private final Date expiration;
    private final Collection<? extends GrantedAuthority> authorities;
}
