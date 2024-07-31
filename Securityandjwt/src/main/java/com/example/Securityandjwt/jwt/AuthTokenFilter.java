package com.example.Securityandjwt.jwt;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class AuthTokenFilter extends OncePerRequestFilter {

    @Autowired
    private JwtUtils jwtUtils;

    @Autowired
    private UserDetailsService userDetails;

    private static  final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        logger.debug("Authentication filter called", request.getRequestURL());
        try{
            String jwt = parseJwt(request);
            if( jwt !=  null && jwtUtils.validateJwtToken(jwt)){
                String Username = jwtUtils.getUsernameFromJwtToken(jwt);

                UserDetails userDetails1 = userDetails.loadUserByUsername(Username);

                UsernamePasswordAuthenticationToken authenticationToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null,
                                userDetails1.getAuthorities());

                logger.debug("Roles from jwt {}", userDetails1.getAuthorities());

                authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }

        }
        catch (Exception e){
            logger.error("Cannot set user authentication {}",e);
        }
        filterChain.doFilter(request,response);
    }
    private String  parseJwt(HttpServletRequest request){
        String jwt = jwtUtils.getJwtFromHeader(request);

        return jwt;
    }
}
