package com.son.spring.jwt.mongodb.security.services;

import com.son.spring.jwt.mongodb.models.BlacklistedToken;
import com.son.spring.jwt.mongodb.security.repository.BlacklistRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.Date;

@Service
public class BlacklistService {

    @Autowired
    private BlacklistRepository blacklistRepository;

    public void addTokenToBlacklist(String token, long ttlMillis) {
        Date expireAt = new Date(System.currentTimeMillis() + ttlMillis);
        BlacklistedToken blacklistedToken = new BlacklistedToken(token, expireAt);
        blacklistRepository.save(blacklistedToken);
    }

    public boolean isTokenBlacklisted(String token) {
        return blacklistRepository.findByToken(token).isPresent();
    }

}
