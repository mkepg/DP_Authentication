package com.mm_mk.Authentication.service;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

@Service
public class RateLimitService {

    private static final Logger logger = LoggerFactory.getLogger(RateLimitService.class);

    private final ConcurrentHashMap<String, Cache<String, AtomicInteger>> caches = new ConcurrentHashMap<>();

    public boolean isAllowed(String key, int limit, Duration window, String category) {
        Cache<String, AtomicInteger> cache = getOrCreateCache(category, window);
        AtomicInteger counter = cache.get(key, k -> new AtomicInteger(0));
        int current = counter.incrementAndGet();

        if (current > limit) {
            logger.debug("Rate limit exceeded: key={}, category={}, count={}/{}", key, category, current, limit);
            return false;
        }
        return true;
    }

    public int getRemaining(String key, int limit, String category) {
        Cache<String, AtomicInteger> cache = caches.get(category);
        if (cache == null) return limit;
        AtomicInteger counter = cache.getIfPresent(key);
        return Math.max(0, limit - (counter != null ? counter.get() : 0));
    }

    private Cache<String, AtomicInteger> getOrCreateCache(String category, Duration window) {
        return caches.computeIfAbsent(category, k ->
                Caffeine.newBuilder()
                        .expireAfterWrite(window)
                        .maximumSize(10_000)
                        .build()
        );
    }
}
