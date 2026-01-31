package com.icar.swc.security;

import java.security.Key;
import java.util.Date;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

    // ✅ LOAD FROM ENV (Railway variable: JWT_SECRET)
    @Value("${jwt.secret}")
    private String secretKey;

    // 24 hours
    private static final long EXPIRATION_TIME =
            24 * 60 * 60 * 1000;

    /* =====================================================
       GENERATE TOKEN (USERNAME)
    ===================================================== */
    public String generateToken(String username) {

        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(new Date())
                .setExpiration(
                        new Date(System.currentTimeMillis() + EXPIRATION_TIME)
                )
                .signWith(getSignKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    /* =====================================================
       GENERATE TOKEN (GOOGLE / AUTH)
    ===================================================== */
    public String generateToken(Authentication authentication) {

        String username;

        if (authentication.getPrincipal() instanceof OAuth2User oauthUser) {
            username = oauthUser.getAttribute("email");
        } else {
            username = authentication.getName();
        }

        return generateToken(username);
    }

    /* =====================================================
       VALIDATE TOKEN (USED BY FILTER)
    ===================================================== */
    public boolean isTokenValid(String token) {
        try {
            extractAllClaims(token);
            return !isTokenExpired(token);
        } catch (Exception e) {
            return false;
        }
    }

    /* =====================================================
       EXTRACT USERNAME
    ===================================================== */
    public String extractUsername(String token) {
        return extractAllClaims(token).getSubject();
    }

    /* =====================================================
       CHECK EXPIRATION
    ===================================================== */
    private boolean isTokenExpired(String token) {
        return extractAllClaims(token)
                .getExpiration()
                .before(new Date());
    }

    /* =====================================================
       PARSE CLAIMS
    ===================================================== */
    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getSignKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /* =====================================================
       SIGNING KEY
    ===================================================== */
    private Key getSignKey() {
        return Keys.hmacShaKeyFor(secretKey.getBytes());
    }
}
