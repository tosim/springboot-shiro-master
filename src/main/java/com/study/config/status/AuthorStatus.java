package com.study.config.status;

public enum AuthorStatus {
    UNAUTHENTICATED(1001),  //未登录认证
    AUTH_LOST(1002),        //登录失效
    PERMISSION_DENIED(1003);


    private Integer code;
    AuthorStatus(Integer code){
        this.code = code;
    }
    public Integer getCode(){
        return this.code;
    }
}
