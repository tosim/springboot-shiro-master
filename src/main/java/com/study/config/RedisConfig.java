package com.study.config;

import lombok.extern.slf4j.Slf4j;
import org.apache.log4j.Logger;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.CachingConfigurerSupport;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.interceptor.KeyGenerator;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.connection.jedis.JedisConnectionFactory;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.serializer.JdkSerializationRedisSerializer;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

import java.io.Serializable;
import java.lang.reflect.Method;

/**
 * Created by yangqj on 2017/4/30.
 */
@Slf4j
@Configuration
@EnableCaching
public class RedisConfig extends CachingConfigurerSupport {
    @Value("${spring.redis.host}")
    private String host;

    @Value("${spring.redis.port}")
    private int port;

    @Value("${spring.redis.password}")
    private String password;

    @Value("${spring.redis.timeout}")
    private int timeout;

    @Value("${spring.redis.pool.max-idle}")
    private int maxIdle;

    @Value("${spring.redis.pool.max-wait}")
    private long maxWaitMillis;

    /**
     * shiro 需要的redis配置
     * @return
     */
    @Bean
    public JedisPool redisPoolFactory() {
        Logger.getLogger(getClass()).info("JedisPool注入成功！！");
        Logger.getLogger(getClass()).info("redis地址：" + host + ":" + port);
        JedisPoolConfig jedisPoolConfig = new JedisPoolConfig();
        jedisPoolConfig.setMaxIdle(maxIdle);
        jedisPoolConfig.setMaxWaitMillis(maxWaitMillis);
        JedisPool jedisPool = new JedisPool(jedisPoolConfig, host, port, timeout);
        return jedisPool;
    }




//    @Bean
//    public CacheManager cacheManager(RedisTemplate<?,?> redisTemplate) {
//        CacheManager cacheManager = new RedisCacheManager(redisTemplate);
//        return cacheManager;
//    }
//
//    @Bean
//    public RedisTemplate<Serializable, Serializable> redisTemplate(
//            JedisConnectionFactory redisConnectionFactory) {
//        log.info("------------------------------------------");
//        log.info("-----------------local redis--------------");
//        log.info("------------------------------------------");
//        RedisTemplate<Serializable, Serializable> redisTemplate = new RedisTemplate<Serializable, Serializable>();
//        //key序列化方式;（不然会出现乱码;）,但是如果方法上有Long等非String类型的话，会报类型转换错误；
//        //所以在没有自己定义key生成策略的时候，以下这个代码建议不要这么写，可以不配置或者自己实现 ObjectRedisSerializer
//        //或者JdkSerializationRedisSerializer序列化方式;
//        redisTemplate.setKeySerializer(new StringRedisSerializer());
//        redisTemplate.setHashKeySerializer(new StringRedisSerializer());
//        redisTemplate
//                .setValueSerializer(new JdkSerializationRedisSerializer());
//        redisTemplate
//                .setHashValueSerializer(new JdkSerializationRedisSerializer());
//        //以上4条配置可以不用
//        redisTemplate.setConnectionFactory(redisConnectionFactory);
//        return redisTemplate;
//    }
//
//    @Bean
//    public JedisConnectionFactory redisConnectionFactory() {
//        JedisConnectionFactory redisConnectionFactory = new JedisConnectionFactory();
//        redisConnectionFactory.setHostName(host);
//        redisConnectionFactory.setPort(port);
//        redisConnectionFactory.setPassword(password);
//
//        return redisConnectionFactory;
//    }
//
//    /**
//     * 自定义key.
//     * 此方法将会根据类名+方法名+所有参数的值生成唯一的一个key
//     */
//    @Override
//    public KeyGenerator keyGenerator() {
//        log.info("RedisCacheConfig.keyGenerator()");
//        return new KeyGenerator() {
//            @Override
//            public Object generate(Object o, Method method, Object... objects){
//                StringBuilder sb = new StringBuilder();
//                sb.append(o.getClass().getName());
//                sb.append(method.getName());
//                for (Object obj : objects) {
//                    sb.append(obj.toString());
//                }
//                log.info("keyGenerator=" + sb.toString());
//                return sb.toString();
//            }
//        };
//    }
}
