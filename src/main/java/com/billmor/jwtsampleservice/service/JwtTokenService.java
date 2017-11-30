package com.billmor.jwtsampleservice.service;

import com.billmor.jwtsampleservice.security.model.JwtUser;
import org.springframework.security.core.userdetails.UserDetails;

public interface JwtTokenService {

    /**
     * Authenticates the token by attempting to parse the token.
     *
     * Validates the token is within its expiration time.
     *
     * returns a PreAuthenticatedAuthenticationToken with the username and the proper authorities.
     * @param authToken
     * @return
     */
    JwtUser authenticateToken(String authToken);

    /**
     * Maps the UserDetails to claims and generates a token
     * @param userDetails
     * @return
     */
    String generateToken(UserDetails userDetails);

    /**
     * refreshes the token provided the oldtoken is valid.
     * @param oldToken
     * @return
     */
    String refreshToken(String oldToken);

}
