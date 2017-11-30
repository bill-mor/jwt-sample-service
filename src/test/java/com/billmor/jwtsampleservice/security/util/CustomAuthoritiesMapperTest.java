package com.billmor.jwtsampleservice.security.util;

import com.billmor.jwtsampleservice.security.model.Roles;
import org.junit.Test;
import org.springframework.security.core.GrantedAuthority;

import java.util.ArrayList;
import java.util.Collection;

import static org.springframework.test.util.AssertionErrors.assertTrue;

public class CustomAuthoritiesMapperTest {

    @Test
    public void TestUSERRoleMapping(){

        CustomAuthoritiesMapper mapper = new CustomAuthoritiesMapper();
        Collection<GrantedAuthority> authorities = new ArrayList<>();

        //user will be a member of group USER
        authorities.add((GrantedAuthority) () -> "USER");

        Collection<? extends GrantedAuthority> roles =  mapper.mapAuthorities(authorities);

        assertTrue("roles should have exactly 1 role", roles.size() == 1);
        assertTrue("roles should have the Roles.ROLE_USER",
                roles.contains(Roles.ROLE_USER));

    }

    @Test
    public void TestADMINRoleMapping(){

        CustomAuthoritiesMapper mapper = new CustomAuthoritiesMapper();
        Collection<GrantedAuthority> authorities = new ArrayList<>();

        //user will be a member of group ADMIN
        authorities.add((GrantedAuthority) () -> "ADMIN");

        Collection<? extends GrantedAuthority> roles =  mapper.mapAuthorities(authorities);

        assertTrue("roles should have exactly 1 role", roles.size() == 1);
        assertTrue("roles should have the Roles.ROLE_ADMIN",
                roles.contains(Roles.ROLE_ADMIN));

    }

}