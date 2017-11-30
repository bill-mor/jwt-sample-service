package com.billmor.jwtsampleservice.controller;

import com.billmor.jwtsampleservice.JwtSampleServiceApplication;
import com.billmor.jwtsampleservice.security.model.JwtAuthenticationRequest;
import com.billmor.jwtsampleservice.security.model.JwtAuthenticationResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.*;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.context.web.WebAppConfiguration;
import org.springframework.web.client.RestTemplate;

import static org.junit.Assert.*;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
public class AuthenticationControllerTest {

    private final String BASE_URL = "http://localhost:8080";
    private final String AUTH_URL = BASE_URL + "/auth/login";

    private RestTemplate restTemplate;

    @Before
    public void init() throws InterruptedException {
        Thread.sleep(500);
        restTemplate = new RestTemplate();
    }

    @Test
    public void testGetToken() throws Exception {

        //build basic auth json object
        String creds = buildCredentials("user", "user");
        HttpHeaders headers = buildHeaders();

        HttpEntity<String> entity = new HttpEntity<String>(creds,headers);

        JwtAuthenticationResponse response = restTemplate.postForEntity(AUTH_URL,
                entity,
                JwtAuthenticationResponse.class)
                .getBody();

        //ensure we get back a token
        assertNotNull(response.getToken());
    }

    private HttpHeaders buildHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        return headers;
    }

    private String buildCredentials(String user, String pass) throws JsonProcessingException {
        return new ObjectMapper()
                .writeValueAsString(
                        new JwtAuthenticationRequest(user, pass));
    }


}