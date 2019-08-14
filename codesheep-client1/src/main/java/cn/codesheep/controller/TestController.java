package cn.codesheep.controller;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import org.apache.commons.lang3.StringUtils;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;
import java.io.UnsupportedEncodingException;

@RestController
public class TestController {
    /*
    curl -X POST -H "authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjE1NTQ0MzExMDgsInVzZXJfbmFtZSI6InVzZXIiLCJhdXRob3JpdGllcyI6WyJST0xFX1VTRVIiXSwianRpIjoiOGM0YWMyOTYtMDQwYS00Y2UzLTg5MTAtMWJmNjZkYTQwOTk3IiwiY2xpZW50X2lkIjoiY2xpZW50YXBwIiwic2NvcGUiOlsicmVhZCJdfQ.YAaSRN0iftmlR6Khz9UxNNEpHHn8zhZwlQrCUCPUmsU" -d 'name=zhangsan' http://localhost:8081/api/hi
    */
    @GetMapping("/normal")
    @PreAuthorize("hasAuthority('ROLE_NORMAL')")
    public String normal( ) {
        String userName = (String) SecurityContextHolder.getContext()
                .getAuthentication().getPrincipal();
        return "normal permission test success !!!" + userName;
    }

    @GetMapping("/medium")
    @PreAuthorize("hasAuthority('ROLE_MEDIUM')")
    public String medium() {
        String userName = (String) SecurityContextHolder.getContext()
                .getAuthentication().getPrincipal();
        return "medium permission test success !!!"+ userName;
    }

    @GetMapping("/admin")
    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    public String admin() {
        return "admin permission test success !!!";
    }



    /**
     * 下面有几种获取方法，可以查看类里面的信息
     * @param userDetails
     * @param authentication
     * @param request
     * @return
     */
    @GetMapping("/me")
    public Object getCurrentUser(@AuthenticationPrincipal UserDetails userDetails, Authentication authentication, HttpServletRequest request) throws UnsupportedEncodingException {
        // Authentication authentication1 = SecurityContextHolder.getContext().getAuthentication();
        // Authorization : bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9
        // 增加了jwt之后，获取传递过来的token
        // 当然这里只是其中一种的 token的传递方法，自己要根据具体情况分析
        String authorization = request.getHeader("Authorization");
        String token = StringUtils.substringAfter(authorization, "bearer ");
        String jwtSigningKey = "testKey";
        // 生成的时候使用的是 org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter
        // 源码里面把signingkey变成utf8了
        // JwtAccessTokenConverter类，解析出来是一个map
        // 所以这个自带的JwtAccessTokenConverter对象也是可以直接用来解析的
        byte[] bytes = jwtSigningKey.getBytes("utf-8");
        Claims body = Jwts.parser().setSigningKey(bytes).parseClaimsJws(token).getBody();

        return body;
    }
}