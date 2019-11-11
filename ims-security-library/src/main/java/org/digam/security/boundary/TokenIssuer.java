package org.digam.security.boundary;

import java.security.Key;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.Date;

import javax.crypto.spec.SecretKeySpec;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class TokenIssuer {
    public static final long EXPIRY_MINS = 60L;

    public String issueToken(String username) {
        LocalDateTime expiryPeriod = LocalDateTime.now().plusMinutes(EXPIRY_MINS);
        Date expirationDateTime = Date.from(
                expiryPeriod.atZone(ZoneId.systemDefault())
                        .toInstant());
        Key key = new SecretKeySpec("secret".getBytes(), "DES");
        String compactJws = Jwts.builder()
                .setSubject(username) 
                .claim("scope", "admin approver") 
                .signWith(SignatureAlgorithm.HS256, key) 
                .setIssuedAt(new Date())
                .setExpiration(expirationDateTime) 
                .compact();
        return compactJws;
    }
}
