package com.billmor.jwtsampleservice.security;

import com.billmor.jwtsampleservice.security.model.JwtTokenRefreshResponceWrapper;
import com.billmor.jwtsampleservice.security.model.JwtUser;
import com.billmor.jwtsampleservice.service.JwtTokenService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class JwtAuthenticationTokenFilter extends OncePerRequestFilter {

    private final Logger logger = LoggerFactory.getLogger(JwtAuthenticationTokenFilter.class);
    private final JwtTokenService jwtTokenService;
    private final String tokenHeader;

    public JwtAuthenticationTokenFilter(JwtTokenService jwtTokenService, String tokenHeader) {
        this.jwtTokenService = jwtTokenService;
        this.tokenHeader = tokenHeader;
    }

    @Override
    public void doFilterInternal(HttpServletRequest request,
                         HttpServletResponse response,
                         FilterChain chain) throws ServletException, IOException {

        String authToken = request.getHeader(this.tokenHeader);
        logger.info("Firewalled Endpoint: " +request.getRequestURI() + " Query: " + request.getQueryString());

        try {

            //attempt to parse user from token
            JwtUser jwtUser = jwtTokenService.authenticateToken(authToken);

            //build authentication from user
            UsernamePasswordAuthenticationToken authentication =
                    new UsernamePasswordAuthenticationToken(jwtUser, null, jwtUser.getAuthorities());

            //add request details
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);

            //add refreshed token to response
            HttpServletResponse tokenResponse = (HttpServletResponse) response;
            JwtTokenRefreshResponceWrapper responseWrapper = new JwtTokenRefreshResponceWrapper(tokenResponse);
            responseWrapper.addHeader(this.tokenHeader, jwtTokenService.refreshToken(authToken));

            chain.doFilter(request, tokenResponse);

        } catch (final ExpiredJwtException expired) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Token is expired");
        } catch (final SignatureException se) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Bad Signature");
        } catch (final Exception e){
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Unauthorized");
        }
    }
}