package com.study;

import org.crazycake.shiro.RedisCacheManager;
import org.crazycake.shiro.RedisSessionDAO;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import javax.annotation.Resource;

@RunWith(SpringRunner.class)
@SpringBootTest
public class SpringbootShiroApplicationTests {

	@Resource
	RedisSessionDAO redisSessionDAO;

	@Resource
	RedisCacheManager redisCacheManager;
	@Test
	public void contextLoads() {
//		redisSessionDAO.getActiveSessions().remove("shiro_redis_session:0b2ee7bc-65e6-4919-b888-5ad3a439cab4");
		redisCacheManager.getCache("shiro_redis_session:0b2ee7bc-65e6-4919-b888-5ad3a439cab4");
	}

}
