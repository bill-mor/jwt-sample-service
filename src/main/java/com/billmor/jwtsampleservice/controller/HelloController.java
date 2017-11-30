package com.billmor.jwtsampleservice.controller;


import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1")
public class HelloController {

    @GetMapping("/user")
    @PreAuthorize("hasRole('ROLE_USER')")
    public String sayHello(){
        return "Hello, USER!";
    }

    @GetMapping("/admin")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public String sayAdminHello(){
        return "Hello, ADMIN!";
    }

}
