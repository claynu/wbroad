package com.best.hello.controller;

import com.wf.captcha.utils.CaptchaUtil;
import io.swagger.annotations.ApiOperation;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

@Controller
public class Login {
    // todo 密码明文写死
    String user = "admin";
    String pass = "admin";

    @ApiOperation(value = "登录")
    @RequestMapping("/user/login")
    public String login(@RequestParam("username") String username, @RequestParam("password") String password, @RequestParam("captcha") String captcha, Model model, HttpSession session, HttpServletRequest request) {

        // 验证码复用
        if (!CaptchaUtil.ver(captcha, request)) {
            CaptchaUtil.clear(request);
            model.addAttribute("msg", "验证码不正确");
            return "login";
        }

        if (user.equals(username) && pass.equals(password)) {
            session.setAttribute("LoginUser", username);
            return "redirect:/index";
        } else {
            model.addAttribute("msg", "用户名或者密码错误");
            return "login";
        }
    }

    @ApiOperation(value = "注销")
    @GetMapping("/user/logout")
    public String logout(HttpSession session) {
        session.invalidate();
        return "redirect:/login";
    }

    @ApiOperation(value = "验证码")
    @GetMapping("/captcha")
    public void captcha(HttpServletRequest request, HttpServletResponse response) throws Exception {
        CaptchaUtil.out(request, response);
    }
}
