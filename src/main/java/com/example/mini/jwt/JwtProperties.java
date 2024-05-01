package com.example.mini.jwt;

public interface JwtProperties {
    public static final String SECRET_KEY = "cosin";
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_STRING = "Authorization";
    public static final int EXPIRATION_TIME = 600000;

}
