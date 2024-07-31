package com.example.Securityandjwt.config;

import com.example.Securityandjwt.jwt.AuthEntryPointJwt;
import com.example.Securityandjwt.jwt.AuthTokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.server.Session;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import javax.sql.DataSource;

import static org.springframework.security.config.Customizer.withDefaults;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class SecurityConfig {



    @Autowired
    DataSource dataSource;

   @Bean
    public AuthTokenFilter authTokenFilter(){
        return new AuthTokenFilter();
    }


    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests((requests) -> requests
                .requestMatchers("/h2-console/**").permitAll()
                .requestMatchers("/authenticate").permitAll()
                .anyRequest().authenticated());

        // SessionManagement
        http.sessionManagement(Session
        -> Session.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        //Form based authentication
//        http.formLogin(withDefaults());

        //Basic authentication
        http.httpBasic(withDefaults());
        http.headers(header ->
                header.frameOptions(frameOptionsConfig -> frameOptionsConfig.sameOrigin()));
        http.csrf(csrf ->
                csrf.disable());
        http.addFilterBefore(authTokenFilter(), UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    // In-Memory Authentication

    @Bean
    public UserDetailsService userDetailsService(){

        UserDetails user1 = User.withUsername("user1")
                .password(passwordEncoder().encode("pass1"))
                .roles("USER")
                .build();


        UserDetails admin = User.withUsername("admin1")
                .password(passwordEncoder().encode("adminPass"))
                .roles("ADMIN")
                .build();

        //Instead of sending in InMemoryManager you can use UserDetailsManager
        JdbcUserDetailsManager userDetailsManager = new JdbcUserDetailsManager(dataSource);

        userDetailsManager.createUser(user1);
        userDetailsManager.createUser(admin);
        return userDetailsManager;


//        return  new InMemoryUserDetailsManager(user1, admin);

    }
    // encode the password
    @Bean
    public PasswordEncoder passwordEncoder(){
        return new BCryptPasswordEncoder();
    }

    // Jwt Authentication
    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration builder) throws Exception{
        return builder.getAuthenticationManager();
    }

}
