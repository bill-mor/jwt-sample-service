package com.billmor.jwtsampleservice.service.impl;

import com.billmor.jwtsampleservice.security.util.CustomAuthoritiesMapper;
import com.billmor.jwtsampleservice.service.JwtTokenService;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.test.context.junit4.SpringRunner;

import javax.annotation.PostConstruct;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.util.ArrayList;
import java.util.Collection;

import static org.junit.Assert.assertTrue;

/**
 * Created by billmoran on 8/21/17.
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
public class JwtTokenServiceTest {


    JwtTokenService jwtTokenService;

    private String issuer;
    private Long expiration;
    private String secretKey;


    @Autowired
    public void initProperty(@Value("${jwt.issuer}") String issuer,
                             @Value("${jwt.secret}") String secretKey,
                             @Value("${jwt.expiration}") Long expiration){
        this.issuer = issuer;
        this.expiration = expiration;
        this.secretKey = secretKey;
    }

    @PostConstruct
    public void postConstruct(){
        CustomAuthoritiesMapper mapper = new CustomAuthoritiesMapper();
        jwtTokenService = new JwtTokenServiceImpl(mapper, issuer, expiration, secretKey);
    }

    @Test
    public void testGenerateValidToken(){

        Collection<GrantedAuthority> authorities = new ArrayList<>();
        //user will be a member of group 90555
        authorities.add((GrantedAuthority) () -> "USER");

        UserDetails user = new User("User", "user", authorities);

        String token = jwtTokenService.generateToken(user);

        System.out.println( "Token: " + token);
        assertTrue("The token cannot be empty", !token.isEmpty());

        try {
            Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token);
        } catch (SignatureException e) {
            assertTrue("The Token was not signed correctly", false);
        }
    }

    @Test
    public void testRefreshValidToken(){

        Collection<GrantedAuthority> authorities = new ArrayList<>();
        //user will be a member of group 90555
        authorities.add((GrantedAuthority) () -> "USER");

        UserDetails user = new User("User", "user", authorities);

        String oldToken = jwtTokenService.generateToken(user);

        String token = jwtTokenService.refreshToken(oldToken);

        assertTrue("The token cannot be empty", !token.isEmpty());
        try {
            Jwts.parser()
                    .setSigningKey(secretKey)
                    .parseClaimsJws(token);
        } catch (SignatureException e) {
            assertTrue("The Token was not signed correctly", false);
        }
    }

    @Test
    public void shouldThrowSignatureError(){

        /*
        this token was generated at https://jwt.io/ using:
        Header:
        {
          "alg": "HS512"
        }

        Payload:
        {
          "com": [
            {
              "authority": "USER"
            }
          ],
          "sub": "User",
          "iss": "bill-mor",
          "exp": 1503421657,
          "iat": 1503420757610
        }
        AND the same signature from a valid token.
        This test ensures the token fails to authenticate.
         */
        String invalidSignatureToken = "eyJhbGciOiJIUzUxMiJ9." +
                "eyJjb20iOlt7ImF1dGhvcml0eSI6IlVTRVIifV0sInN1YiI6IlVzZXIiLCJpc3MiOiJiaWxsLW1vciIsImV4cCI6MTUxMjAwMDUyMiwiaWF0IjoxNTExOTk4NzIyMjIxfQ." +
                "dSnwOXhByHcnOIXYb8iZzTitna6IQcNfqh85jBmKLu8";

        try {
            jwtTokenService.authenticateToken(invalidSignatureToken);
            assertTrue("The Token was successfully used to Authenticate -> expected outcome was SignatureException", false);
        } catch (SignatureException e) {
            assertTrue("The Token was not allowed to Authenticate!", true);
        }

    }

    @Test
    public void shouldThrowMalformedJwtErrorOnTokenWithAlgNONE(){

        /*
        this token was generated at https://jwt.io/ using:
        Header:
        {
          "alg": "none"
        }

        Payload:
        {
          "com": [
            {
              "authority": "USER"
            }
          ],
          "sub": "User",
          "iss": "bill-mor",
          "exp": 1503421657,
          "iat": 1503420757610
        }
        AND the same signature from a valid token.
        This test ensures the token fails to authenticate.
         */
        String malformedJwtToken = "eyJhbGciOiJub25lIn0." +
                "eyJjb20iOlt7ImF1dGhvcml0eSI6IlVTRVIifV0sInN1YiI6IlVzZXIiLCJpc3MiOiJiaWxsLW1vciIsImV4cCI6MTUxMjAwMDUyMiwiaWF0IjoxNTExOTk4NzIyMjIxfQ." +
                "2TCb0J6EsZXR14XPg2ndFASc2ceVFYRjZLFotpChRvg";

        try {
            jwtTokenService.authenticateToken(malformedJwtToken);
            assertTrue("The Token was successfully used to Authenticate -> expected outcome was MalformedJwtException", false);
        } catch (MalformedJwtException e) {
            assertTrue("The Token was not allowed to Authenticate!", true);
        }

    }

}