package com.mm_mk.Authentication.util;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtUtils {

    private final RSAPrivateKey privateKey;

    public JwtUtils() throws Exception {
        // Load private.pem from resources/certifications/
        ClassPathResource resource = new ClassPathResource("certifications/private.pem");
        String privateKeyContent;

        try (InputStream inputStream = resource.getInputStream()) {
            privateKeyContent = new String(inputStream.readAllBytes())
                    .replaceAll("-----BEGIN (.*)-----", "")
                    .replaceAll("-----END (.*)-----", "")
                    .replaceAll("\\s", "");
        }

        byte[] decodedPrivate = Base64.getDecoder().decode(privateKeyContent);
        PKCS8EncodedKeySpec keySpecPrivate = new PKCS8EncodedKeySpec(decodedPrivate);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        this.privateKey = (RSAPrivateKey) kf.generatePrivate(keySpecPrivate);
    }

    public String generateToken(UserDetails userDetails) {
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 2)) // 2h
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }
}
