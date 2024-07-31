package com.example.Securityandjwt.jwt;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import jakarta.servlet.http.HttpServletRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.security.Key;
import java.util.Base64;
import java.util.Date;

//import static jdk.internal.org.jline.keymap.KeyMap.key;

@Component
public class JwtUtils {
    private static  final Logger logger = LoggerFactory.getLogger(JwtUtils.class);

    @Value("${spring.app.jwtsecret}")
    private String jwtSecret;

    @Value(("${spring.app.jwtExpirationMs}"))
    private int jwtExpirationMs;



    public String getJwtFromHeader (HttpServletRequest request){
        String bearerToken = request.getHeader("Authorization");
        logger.debug("Authorization header: {}", bearerToken);
        if( bearerToken != null  && bearerToken.startsWith("Bearer")) {
            return bearerToken.substring(7);
        }
        return null;
    }
    public String generateTokenFromUsername(UserDetails userDetails) {
        return generateTokenFromUsername(userDetails.getUsername());
    }

    public String generateTokenFromUsername(String username) {
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(new Date((new Date()).getTime() + jwtExpirationMs))
                .signWith(SignatureAlgorithm.HS512, jwtSecret)
                .compact();
    }

    public String getUsernameFromJwtToken(String token) {
        return Jwts.parser()

                .verifyWith((SecretKey) key()).build().parseSignedClaims(token)
                .getPayload().getSubject();

    }

    private Key key() {
        return Keys.hmacShaKeyFor(Decoders.BASE64.decode(jwtSecret));
    }
    public boolean validateJwtToken(String authToken){
        try{
            System.out.println("validate");
            Jwts.parser().verifyWith((SecretKey) key()).build().parseSignedClaims(authToken);
                    return true;
        }catch (MalformedJwtException e){
            logger.error("Invalid Jwt Token", e.getMessage());

        }catch (ExpiredJwtException e){
            logger.error("Token is expired ", e.getMessage());
        }
        catch (UnsupportedJwtException e){
            logger.error("Jwt Token is unsupported", e.getMessage());
        }
        return  false;
    }

}
