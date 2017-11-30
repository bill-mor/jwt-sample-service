package com.billmor.jwtsampleservice.security.util;

import com.billmor.jwtsampleservice.security.model.Roles;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.mapping.GrantedAuthoritiesMapper;
import org.springframework.stereotype.Component;

import java.util.Collection;
import java.util.EnumSet;
import java.util.Set;


@Component
public class CustomAuthoritiesMapper implements GrantedAuthoritiesMapper {

    public Collection<? extends GrantedAuthority> mapAuthorities(Collection<? extends GrantedAuthority> authorities) {
        Set<Roles> roles = EnumSet.noneOf(Roles.class);

        for (GrantedAuthority a: authorities) {
            if (a.getAuthority().equalsIgnoreCase("ADMIN")) {
                roles.add(Roles.ROLE_ADMIN);
            }
            if (a.getAuthority().equalsIgnoreCase("USER")) {
                roles.add(Roles.ROLE_USER);
            }
        }

        return roles;
    }
}
