package com.study.shiro;

import com.study.mapper.UserMapper;
import com.study.model.Resources;
import com.study.model.User;
import com.study.service.ResourcesService;
import com.study.service.UserService;
import com.study.util.PasswordHelper;
import lombok.extern.slf4j.Slf4j;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.cache.Cache;
import org.apache.shiro.cache.CacheManager;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.session.Session;
import org.apache.shiro.session.mgt.DefaultSessionKey;
import org.apache.shiro.session.mgt.SessionManager;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.subject.SimplePrincipalCollection;
import org.apache.shiro.subject.support.DefaultSubjectContext;
import org.apache.shiro.util.ByteSource;
import org.crazycake.shiro.RedisSessionDAO;
import org.springframework.beans.factory.annotation.Autowired;

import javax.annotation.Resource;
import java.util.*;

/**
 * Created by yangqj on 2017/4/21.
 */
@Slf4j
public class MyShiroRealm extends AuthorizingRealm {
    @Resource
    UserMapper userMapper;

    @Resource
    private UserService userService;

    @Resource
    private ResourcesService resourcesService;

    @Autowired
    private RedisSessionDAO redisSessionDAO;

    private CacheManager cacheManager;
    private RealmSecurityManager securityManager;

    @Override
    public void setCacheManager(CacheManager cacheManager) {
        this.cacheManager = cacheManager;
    }

    public void setSecurityManager(RealmSecurityManager securityManager) {
        this.securityManager = securityManager;
    }

    //授权
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {
        log.debug("登录成功之后开始授权");
        User user= (User) SecurityUtils.getSubject().getPrincipal();//User{id=1, username='admin', password='3ef7164d1f6167cb9f2658c07d3c2f0a', enable=1}
        log.debug(""+user.getId());
        Map<String,Object> map = new HashMap<String,Object>();
        map.put("userid",user.getId());
        List<Resources> resourcesList = resourcesService.loadUserResources(map);
        // 权限信息对象info,用来存放查出的用户的所有的角色（role）及权限（permission）
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        for(Resources resources: resourcesList){
            info.addStringPermission(resources.getResurl());
        }
        return info;
    }

    //认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        //获取用户的输入的账号.
        //log.debug("登录时候的认证～～～"+"username = " + String.valueOf(token.getPrincipal()) + ", pass = " + new String((char[])token.getCredentials()));
        String username = (String)token.getPrincipal();
        String password = new String((char[])token.getCredentials());

        User user = userService.selectByUsername(username);
        if(user==null) throw new UnknownAccountException();
        if (0==user.getEnable()) {
            throw new LockedAccountException(); // 帐号锁定
        }

        SimpleAuthenticationInfo authenticationInfo;
        String encryptPassword = PasswordHelper.encryptPassword(username,password);

        //如果密码等于token
        if(encryptPassword.equals(user.getToken())){
            authenticationInfo = new SimpleAuthenticationInfo(
                    user, //用户
                    user.getToken(), //使用数据库中的token作为登录凭据
                    ByteSource.Util.bytes(username),
                    getName()  //realm name
            );
        }else{
            authenticationInfo = new SimpleAuthenticationInfo(
                    user, //用户
                    user.getPassword(), //使用密码作为登录凭据
                    ByteSource.Util.bytes(username),
                    getName()  //realm name
            );
        }

        //如果登录成功,清楚上一次的权限缓存，将上次登录的session设置属性kickout，防止上次会话再次使用，实现踢出登录
        if(encryptPassword.equals(user.getToken()) || encryptPassword.equals(user.getPassword())){
            // 当验证都通过后，把用户信息放在session里,更新数据库的token
            Session session = SecurityUtils.getSubject().getSession();
            RealmSecurityManager securityManager = (RealmSecurityManager) SecurityUtils.getSecurityManager();
            CacheManager cacheManager = securityManager.getCacheManager();

            List<Integer> tmp = new ArrayList<Integer>();
            tmp.add(user.getId());
            clearUserAuthByUserId(tmp);//清除之前的授权信息
            //==========================
            Cache<String,String> cache = cacheManager.getCache("shiro-kickout-session");
            String kickSessionId = cache.get(user.getUsername());//获得要踢出的sessionId;
            Session kickoutSession = securityManager.getSession(new DefaultSessionKey(kickSessionId));
            if(kickoutSession != null) {
                //设置会话的kickout属性表示踢出了
                kickoutSession.setAttribute("kickout", true);
            }
            cache.put(user.getUsername(),session.getId().toString());//设置新的sessionId
            //==========================

            user.setToken(PasswordHelper.encryptPassword(user.getUsername(),session.getId().toString()));
            System.out.println("update table user"+user.getId()+" token" + user.getToken());

            userMapper.updateByPrimaryKeySelective(user);//更新数据库token
            session.setAttribute("userSession", user);
            session.setAttribute("userSessionId", user.getId());
        }

        return authenticationInfo;
    }


    /**
     * 根据userId 清除当前session存在的用户的权限缓存
     * @param userIds 已经修改了权限的userId
     */
    public void clearUserAuthByUserId(List<Integer> userIds){
        if(null == userIds || userIds.size() == 0)	return ;
        //获取所有session
        Collection<Session> sessions = redisSessionDAO.getActiveSessions();
        //定义返回
        List<SimplePrincipalCollection> list = new ArrayList<SimplePrincipalCollection>();
        for (Session session:sessions){
            //获取session登录信息。
            Object obj = session.getAttribute(DefaultSubjectContext.PRINCIPALS_SESSION_KEY);
            if(null != obj && obj instanceof SimplePrincipalCollection){
                //强转
                SimplePrincipalCollection spc = (SimplePrincipalCollection)obj;
                //判断用户，匹配用户ID。
                obj = spc.getPrimaryPrincipal();
                if(null != obj && obj instanceof User){
                    User user = (User) obj;
                    System.out.println("user:"+user);
                    //比较用户ID，符合即加入集合
                    if(null != user && userIds.contains(user.getId())){
                        list.add(spc);
                    }
                }
            }
        }
        RealmSecurityManager securityManager =
                (RealmSecurityManager) SecurityUtils.getSecurityManager();
        MyShiroRealm realm = (MyShiroRealm)securityManager.getRealms().iterator().next();
        for (SimplePrincipalCollection simplePrincipalCollection : list) {
            realm.clearCachedAuthorizationInfo(simplePrincipalCollection);
        }


    }
}
