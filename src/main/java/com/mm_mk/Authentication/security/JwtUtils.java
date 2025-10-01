package com.mm_mk.Authentication.security;

import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;

@Component
public class JwtUtils {
    private final RSAPrivateKey privateKey;
    private final RSAPublicKey publicKey;

    public JwtUtils() throws Exception {
        // Load private key
        String privateKeyContent = new String(Files.readAllBytes(
                Paths.get(new ClassPathResource("private.pem").getURI())))
                .replaceAll("-----\\w+ PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decodedPrivate = Base64.getDecoder().decode(privateKeyContent);
        PKCS8EncodedKeySpec keySpecPrivate = new PKCS8EncodedKeySpec(decodedPrivate);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        this.privateKey = (RSAPrivateKey) kf.generatePrivate(keySpecPrivate);

        // Load public key
        String publicKeyContent = new String(Files.readAllBytes(
                Paths.get(new ClassPathResource("public.pem").getURI())))
                .replaceAll("-----\\w+ PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decodedPublic = Base64.getDecoder().decode(publicKeyContent);
        X509EncodedKeySpec keySpecPublic = new X509EncodedKeySpec(decodedPublic);
        this.publicKey = (RSAPublicKey) kf.generatePublic(keySpecPublic);
    }

    public String generateToken(UserDetails userDetails) {
        return Jwts.builder()
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date())
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 2)) // 2h
                .signWith(privateKey, SignatureAlgorithm.RS256)
                .compact();
    }

    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(token);
            return true;
        } catch (JwtException e) {
            return false;
        }
    }

    public String extractUsername(String token) {
        return Jwts.parserBuilder().setSigningKey(publicKey).build()
                .parseClaimsJws(token).getBody().getSubject();
    }
}
