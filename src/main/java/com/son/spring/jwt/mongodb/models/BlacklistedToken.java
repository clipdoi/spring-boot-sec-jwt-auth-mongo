package com.son.spring.jwt.mongodb.models;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.index.Indexed;
import org.springframework.data.mongodb.core.mapping.Document;

import java.util.Date;

@Document(collection = "blacklistedTokens")
public class BlacklistedToken {

    @Id
    private String id;
    private String token;

    @Indexed(name = "expireAt", expireAfterSeconds = 3600) // Token sẽ bị xóa sau 1 giờ (3600 giây)
    private Date expireAt;

    public BlacklistedToken() {}

    public BlacklistedToken(String token, Date expireAt) {
        this.token = token;
        this.expireAt = expireAt;
    }

    // Getter và Setter
    public String getToken() {
        return token;
    }

    public void setToken(String token) {
        this.token = token;
    }

    public Date getExpireAt() {
        return expireAt;
    }

    public void setExpireAt(Date expireAt) {
        this.expireAt = expireAt;
    }

}
