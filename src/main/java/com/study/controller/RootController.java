package com.study.controller;

import com.study.config.status.AuthorStatus;
import com.study.dto.RespJson;
import com.study.mapper.UserMapper;
import com.study.model.User;
import com.study.service.UserService;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.IncorrectCredentialsException;
import org.apache.shiro.authc.LockedAccountException;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.UnauthenticatedException;
import org.apache.shiro.authz.UnauthorizedException;
import org.apache.shiro.authz.annotation.RequiresPermissions;
import org.apache.shiro.authz.annotation.RequiresUser;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import javax.annotation.Resource;
import java.util.HashMap;
import java.util.Map;


@RestController
@RequestMapping("/api")
public class RootController {
    @Autowired
    UserService userService;

    @Resource UserMapper userMapper;


//    @RequiresUser
    @RequiresPermissions("/usersPage")
    @RequestMapping(value = "/testget",method = RequestMethod.GET)
    public RespJson test(){
        //Subject subject = SecurityUtils.getSubject();
        //System.out.println("sessionId = "+subject.getSession().getId());
        //User user = (User)subject.getSession().getAttribute("userSession");
        //subject.getSession().setAttribute("test",tid);

        //if(subject.getSession(false) == null){
          //  return new RespJson("ok","test ok",200);
        //}
        return new RespJson("ok","test ok",200);
    }

    @RequiresUser
    @RequestMapping(value = "/testput",method = RequestMethod.GET)
    public RespJson test(@RequestParam Integer tid){
        Subject subject = SecurityUtils.getSubject();
        System.out.println("sessionId = "+subject.getSession().getId());
        User user = (User)subject.getSession().getAttribute("userSession");
        subject.getSession().setAttribute("test",tid);
        return new RespJson(subject.getSession().getAttribute("test"),"test ok",200);
    }

//    @RequestMapping(value = "/register")
//    public String register(@RequestBody User user) {
//        User u = userService.selectByUsername(user.getUsername());
//        if(u != null)
//            return "error";
//        try {
//            user.setEnable(1);
//            PasswordHelper passwordHelper = new PasswordHelper();
//            passwordHelper.encryptPassword(user);
//            userService.save(user);
//            return "success";
//        } catch (Exception e) {
//            e.printStackTrace();
//            return "fail";
//        }
//    }

    @RequestMapping(value = "/sessions",method = RequestMethod.POST)
    public RespJson login(@RequestBody User user){
        RespJson respJson = new RespJson();
        Subject subject = SecurityUtils.getSubject();
        System.out.println("pass = " + user.getPassword());
        UsernamePasswordToken token = new UsernamePasswordToken(user.getUsername(), user.getPassword());
        try {
            subject.login(token);
            Map<String,Object> data = new HashMap<String,Object>();
            data.put("token",subject.getSession().getId());
            respJson.setData(data);
            respJson.setMsg("登录成功");
            respJson.setCode(200);

        } catch (IncorrectCredentialsException e) {
            respJson.setMsg("密码错误");
        } catch (LockedAccountException e) {
            respJson.setMsg("登录失败，该账户被冻结");
        } catch (AuthenticationException e) {
            respJson.setMsg("用户不存在");
        } catch (Exception e) {
            e.printStackTrace();
        }
        return respJson;
    }

    @RequiresUser
    @RequestMapping(value = "/sessions/{id}",method = RequestMethod.DELETE)
    public RespJson login(@PathVariable String id){
        Subject subject = SecurityUtils.getSubject();
        RespJson respJson = new RespJson(null,null,1001);
        Session session = subject.getSession(false);
        if(session == null){
            respJson.setMsg("用户未登录");
            return respJson;
        }

        //User user = (User)subject.getSession().getAttribute("userSession");
        if(session.getId().equals(id)){
            subject.logout();
            respJson.setMsg("注销成功");
            respJson.setCode(200);
            return respJson;
        }else {
            respJson.setMsg("错误的id");
            return respJson;
        }
    }

    /**
     *
     * @return
     */
//    @RequestMapping(value = "/unauth",method = RequestMethod.GET)
//    public RespJson unauth() {
//        RespJson respJson = new RespJson(null, AuthorStatus.UNAUTHENTICATED.name(),AuthorStatus.UNAUTHENTICATED.getCode());//未登录用户
//        return respJson;
//    }

    @RequestMapping(value = "/authLose",method = RequestMethod.GET)
    public RespJson authLose() {
        RespJson respJson = new RespJson(null,AuthorStatus.AUTH_LOST.name(),AuthorStatus.AUTH_LOST.getCode());//登录失效
        return respJson;
    }


    @ExceptionHandler({UnauthorizedException.class})
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public RespJson unauthorized() {
        RespJson respJson = new RespJson(null,AuthorStatus.PERMISSION_DENIED.name(),AuthorStatus.PERMISSION_DENIED.getCode());//权限不够
        return respJson;
    }

    @ExceptionHandler({UnauthenticatedException.class})
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public RespJson unauthenticated() {
        RespJson respJson = new RespJson(null,AuthorStatus.UNAUTHENTICATED.name(),AuthorStatus.UNAUTHENTICATED.getCode());
        return respJson;
    }
}


