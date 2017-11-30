package com.billmor.jwtsampleservice.config;


import com.billmor.jwtsampleservice.security.JwtAuthEntryPoint;
import com.billmor.jwtsampleservice.security.JwtAuthenticationTokenFilterFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;


@SuppressWarnings("SpringJavaAutowiringInspection")
@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {


    private final JwtAuthEntryPoint entryPointHandler;
    private final JwtAuthenticationTokenFilterFactory filterFactory;

    @Autowired
    public WebSecurityConfig(JwtAuthEntryPoint entryPointHandler,
                             JwtAuthenticationTokenFilterFactory filterFactory) {
        this.entryPointHandler = entryPointHandler;
        this.filterFactory = filterFactory;
    }


    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser("user").password("user").authorities((GrantedAuthority) () -> "USER")
                .and()
                .withUser("admin").password("admin").authorities((GrantedAuthority) () -> "ADMIN");
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        web.ignoring().antMatchers("/auth/login");
    }

    @Override
    public void configure(HttpSecurity http) throws Exception {
            http
                .csrf()
                    .disable()
                .exceptionHandling()
                    .authenticationEntryPoint(entryPointHandler)
                    .and()
                .sessionManagement()
                    .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                    .and()
                .addFilterBefore(filterFactory.build(), BasicAuthenticationFilter.class)
                .authorizeRequests()
                    .anyRequest()
                    .authenticated();
    }
}
