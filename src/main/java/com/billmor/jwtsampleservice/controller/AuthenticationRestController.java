package com.billmor.jwtsampleservice.controller;


import com.billmor.jwtsampleservice.security.model.JwtAuthenticationRequest;
import com.billmor.jwtsampleservice.security.model.JwtAuthenticationResponse;
import com.billmor.jwtsampleservice.service.JwtTokenService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.*;

@RestController
public class AuthenticationRestController {

    private final Logger logger = LoggerFactory.getLogger(AuthenticationRestController.class);
    private final String tokenHeader;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenService jwtTokenService;

    @Autowired
    public AuthenticationRestController(AuthenticationManager authenticationManager,
                                        JwtTokenService jwtTokenService,
                                        @Value("${jwt.header}") String tokenHeader) {
        this.authenticationManager = authenticationManager;
        this.jwtTokenService = jwtTokenService;
        this.tokenHeader = tokenHeader;
    }

    @PostMapping(value = "${jwt.route.authentication.path}")
    public ResponseEntity<?> createAuthenticationToken(@RequestBody JwtAuthenticationRequest authenticationRequest) throws AuthenticationException {

        //authenticate the user
        final Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        authenticationRequest.getUsername(),
                        authenticationRequest.getPassword()
                )
        );

        //apply the authentication to the context
        SecurityContextHolder.getContext().setAuthentication(authentication);

        //build and return the token
        return ResponseEntity.ok(
                new JwtAuthenticationResponse(
                        jwtTokenService.generateToken(
                                (UserDetails) authentication.getPrincipal()
                        )
                )
        );
    }

    @ResponseStatus(value = HttpStatus.FORBIDDEN, reason = "Invalid Login")
    @ExceptionHandler(BadCredentialsException.class)
    public void loginError() {
        // Nothing to do inside exception handler
        // Returns a 403 for invalid login requests
    }

}