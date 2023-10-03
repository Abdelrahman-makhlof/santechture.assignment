package com.santechture.api.security;

import com.santechture.api.entity.Admin;
import org.springframework.stereotype.Component;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.util.Assert;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.SignatureException;
import io.jsonwebtoken.UnsupportedJwtException;

import javax.servlet.http.HttpServletRequest;
import java.util.Calendar;
import java.util.Date;

@Component
public class JwtTokenUtil {

    final String SECRET_KEY = "A43279F58582D9FFA4A5ADA8B87DB";
    public static final long JWT_TOKEN_VALIDITY = 1000 * 60 * 24;


    private static String TOKEN_SECRET;
    private static Long ACCESS_TOKEN_VALIDITY;

    public JwtTokenUtil(@Value("${spring.auth.secret}") String secret, @Value("${spring.auth.access.expiration}") Long accessValidity
            , @Value("${spring.auth.refresh.expiration}") Long refreshValidity) {
        Assert.notNull(accessValidity, "Validity must not be null");
        Assert.hasText(secret, "Validity must not be null or empty");

        TOKEN_SECRET = secret;
        ACCESS_TOKEN_VALIDITY = accessValidity;
    }

    public static String generateToken(final String username, final String tokenId ) {
        return Jwts.builder()
                .setId(tokenId)
                .setSubject(username)
                .setIssuedAt(new Date())
                .setIssuer("app-Service")
                .setExpiration(calcTokenExpirationDate())
                .claim("created", Calendar.getInstance().getTime())
                .signWith(SignatureAlgorithm.HS512, TOKEN_SECRET).compact();
    }


    private static Date calcTokenExpirationDate() {
        return new Date(System.currentTimeMillis() +  ACCESS_TOKEN_VALIDITY * 1000);
    }

    public String getUserNameFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.getSubject();
    }

    public String getTokenIdFromToken(String token) {
        return getClaims(token).getId();
    }

    public boolean isTokenValid(String token, Admin userDetails) {
//        log.info("isTokenExpired >>> " + isTokenExpired(token));
        String username = getUserNameFromToken(token);
//        log.info("username from token >>> " + username);
//        log.info("userDetails.getUsername >>> " + userDetails.getUsername());
//        log.info("username =  >>> userDetails.getUsername >>> " + username.equals(userDetails.getUsername()));
        Boolean isUserNameEqual = username.equalsIgnoreCase(userDetails.getUsername()) ;
        return (isUserNameEqual && !isTokenExpired(token));
    }

    public boolean isTokenExpired(String token) {
        Date expiration = getClaims(token).getExpiration();
        return expiration.before(new Date());
    }

    private Claims getClaims(String token) {

        return Jwts.parser().setSigningKey(TOKEN_SECRET).parseClaimsJws(token).getBody();
    }


    public boolean validateToken(String token , HttpServletRequest httpServletRequest){

        try {
            Jwts.parser().setSigningKey(TOKEN_SECRET).parseClaimsJws(token);
            return true;
        }catch (SignatureException ex){
//            log.info("Invalid JWT Signature");
            //  throw new SecurityException("Invalid JWT Signature");
        }catch (MalformedJwtException ex){
//            log.info("Invalid JWT token");
            httpServletRequest.setAttribute("expired",ex.getMessage());
            //  throw new SecurityException("Invalid JWT token");
        }catch (ExpiredJwtException ex){
//            log.info("Expired JWT token");
            httpServletRequest.setAttribute("expired",ex.getMessage());
            //  throw new SecurityException("security.token_expired");
        }catch (UnsupportedJwtException ex){
//            log.info("Unsupported JWT exception");
            //   throw new SecurityException("Unsupported JWT exception");
        }catch (IllegalArgumentException ex){
//            log.info("Jwt claims string is empty");
            //   throw new SecurityException("Jwt claims string is empty");
        }
        return false;
    }

}
