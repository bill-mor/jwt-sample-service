package com.billmor.jwtsampleservice.controller;

import com.billmor.jwtsampleservice.security.model.JwtAuthenticationRequest;
import com.billmor.jwtsampleservice.security.model.JwtAuthenticationResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringJUnit4ClassRunner;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.web.client.RestTemplate;

import static org.junit.Assert.*;


@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
public class HelloControllerTest {

    private final String BASE_URL = "http://localhost:8080";
    private final String AUTH_URL = BASE_URL + "/auth/login";
    private final String USER_URL = BASE_URL + "/api/v1/user";
    private final String ADMIN_URL = BASE_URL + "/api/v1/admin";
    private String AUTH_HEADER;

    private RestTemplate restTemplate;

    @Autowired
    public void initProperty(@Value("${jwt.header}") String authHeader ) {
        this.AUTH_HEADER = authHeader;
    }

    @Before
    public void init() throws InterruptedException {
        Thread.sleep(500);
        restTemplate = new RestTemplate();
    }

    @Test
    public void testAuthorizationOnUserController() throws Exception {

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(AUTH_HEADER, getToken("user", "user"));

        HttpEntity<String> entity = new HttpEntity<String>(headers);

        String responce = restTemplate.exchange(
                USER_URL,
                HttpMethod.GET,
                entity,
                String.class)
                .getBody();

        assertTrue(responce.equalsIgnoreCase("Hello, USER!"));
    }

    @Test
    public void testAuthorizationOnAdminController() throws Exception {

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(AUTH_HEADER, getToken("admin", "admin"));

        HttpEntity<String> entity = new HttpEntity<String>(headers);

        String responce = restTemplate.exchange(
                ADMIN_URL,
                HttpMethod.GET,
                entity,
                String.class)
                .getBody();

        assertTrue(responce.equalsIgnoreCase("Hello, ADMIN!"));
    }



    private String getToken(String user, String pass) throws Exception {
        //build basic auth json object
        String creds = buildCredentials(user, pass);
        HttpHeaders headers = buildHeaders();

        HttpEntity<String> entity = new HttpEntity<String>(creds,headers);

        JwtAuthenticationResponse response = restTemplate.postForEntity(AUTH_URL,
                entity,
                JwtAuthenticationResponse.class)
                .getBody();

        return response.getToken();
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