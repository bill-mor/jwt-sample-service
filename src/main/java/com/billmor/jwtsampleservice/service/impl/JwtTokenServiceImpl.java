package com.billmor.jwtsampleservice.service.impl;

import com.billmor.jwtsampleservice.security.model.JwtUser;
import com.billmor.jwtsampleservice.security.util.CustomAuthoritiesMapper;
import com.billmor.jwtsampleservice.service.JwtTokenService;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import java.util.*;
import java.util.stream.Collectors;

@Service
public class JwtTokenServiceImpl implements JwtTokenService {

    private final Log logger = LogFactory.getLog(this.getClass());

    private final CustomAuthoritiesMapper customAuthoritiesMapper;

    private static final String CLAIM_KEY_USERNAME = "sub";
    private static final String CLAIM_KEY_AUTHORITIES = "com";
    private static final String CLAIM_KEY_CREATED = "iat";
    private static final String CLAIM_KEY_ISSUER = "iss";
    private static final String HEADER_KEY_TYPE = "typ";
    private static final String HEADER_VALUE_TYPE = "JWT";

    private static String secretKey;
    private static Long expiration;
    private static String issuer;


    @Autowired
    public JwtTokenServiceImpl(CustomAuthoritiesMapper customAuthoritiesMapper,
                               @Value("${jwt.issuer}") String issuer,
                               @Value("${jwt.expiration}") Long expiration,
                               @Value("${jwt.secret}") String secretKey) {
        this.customAuthoritiesMapper = customAuthoritiesMapper;
        this.secretKey = secretKey;
        this.expiration = expiration;
        this.issuer = issuer;
    }


    /**
     * defines the JWT signature algorithm we will be using to sign the token
     *
     * generates the secret key spec,
     *
     */
    private final SignatureAlgorithm signatureAlgorithm = SignatureAlgorithm.HS512;
    private SecretKeySpec generateSecret() {
        //We will sign our JWT with our ApiKey secret
        byte[] apiKeySecretBytes = DatatypeConverter.parseBase64Binary(secretKey);
        return new SecretKeySpec(apiKeySecretBytes, signatureAlgorithm.getJcaName());
    }



    /**
     * Authenticates the token by attempting to parse the token.
     *
     * Validates the token is within its expiration time.
     *
     * returns a PreAuthenticatedAuthenticationToken with the username and the proper authorities.
     * @param authToken
     * @return
     */
    @Override
    public JwtUser authenticateToken(String authToken) throws SignatureException {

        return parseToken(authToken);

    }

    /**
     * Maps the UserDetails to claims and generates a token
     * @param userDetails
     * @return
     */
    @Override
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();


        claims.put(CLAIM_KEY_USERNAME, userDetails.getUsername());
        claims.put(CLAIM_KEY_AUTHORITIES, userDetails.getAuthorities());
        claims.put(CLAIM_KEY_CREATED, new Date(System.currentTimeMillis()));
        claims.put(CLAIM_KEY_ISSUER, issuer);

        logger.info("User Details: " + userDetails.toString() );
        logger.info("claims: " + claims.toString() );

        return doGenerateToken(claims);
    }

    @Override
    public String refreshToken(String oldToken) {
        Map<String, Object> claims = getClaimsFromToken(oldToken);
        claims.put(CLAIM_KEY_CREATED, new Date(System.currentTimeMillis()));

        logger.info("claims: " + claims.toString() );

        return doGenerateToken(claims);
    }

    /////////////////////////////////  PRIVATE HELPERS  ////////////////////////////////////////

    private String doGenerateToken(Map<String, Object> claims) {
        final Date createdDate = (Date) claims.get(CLAIM_KEY_CREATED);
        final Date expirationDate = new Date(createdDate.getTime() + expiration);

        Map<String, String> headers = new HashMap<>();
        headers.put(HEADER_KEY_TYPE, HEADER_VALUE_TYPE);

        return Jwts.builder()
                .setClaims(claims)
                .setExpiration(expirationDate)
                .signWith(signatureAlgorithm, generateSecret())
                .compact();
    }

    private JwtUser parseToken(String authToken) {

        Claims claims = getClaimsFromToken(authToken);

        return JwtUser.builder()
                .issuer(getIssuerFromClaims(claims))
                .username(getUserNameFromClaims(claims))
                .authorities(getAuthoritiesFromClaims(claims))
                .expiration(getExpiration(claims))
                .build();
    }

    private Claims getClaimsFromToken(String token) {
        return Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token)
                .getBody();

    }

    private String getIssuerFromClaims(Claims claims) {
        String issuer;
        try {
            issuer = claims.getIssuer();
        } catch (final Exception e) {
            issuer = null;
        }
        return issuer;
    }

    private Date getExpiration(Claims claims) {
        Date expiration;
        try {
            expiration = claims.getExpiration();
        } catch (final Exception e) {
            expiration = null;
        }
        return expiration;
    }

    private String getUserNameFromClaims(Claims claims) {

        String username;
        try {
            username = (String) claims.get(CLAIM_KEY_USERNAME);
        } catch (final Exception e) {
            username = null;
        }
        return username;
    }

    /**
     * Uses the CustomAuthoritiesMapper to map the CID from the UserDetails authorities to the correct ROLE_USER
     */
    private Collection<? extends GrantedAuthority> getAuthoritiesFromClaims(Claims claims) {
        Collection<? extends GrantedAuthority> authorities;
        try {
            authorities = Arrays.asList(claims.get(CLAIM_KEY_AUTHORITIES).toString().split(",")).stream()
                    .map(authority -> new SimpleGrantedAuthority(parseAuthority(authority)))
                    .collect(Collectors.toList());
            //apply custom mapper
            authorities = customAuthoritiesMapper.mapAuthorities(authorities);
        } catch (final Exception e) {
            authorities = null;
        }
        return authorities;
    }

    private String parseAuthority(String authority) {
        return authority.replaceAll("authority=","").split("\\{")[1].split("}")[0];
    }


}