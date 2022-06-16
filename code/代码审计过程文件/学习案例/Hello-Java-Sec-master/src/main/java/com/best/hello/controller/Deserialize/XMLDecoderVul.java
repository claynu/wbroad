package com.best.hello.controller.Deserialize;

import io.swagger.annotations.ApiOperation;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.beans.XMLDecoder;
import java.beans.XMLEncoder;
import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.util.HashMap;

@Slf4j
@RestController
@RequestMapping("/Deserialize/XMLDecoder")
public class XMLDecoderVul {

    /**
     * XMLDecoder 是JDK的一个对象转XML的工具。所以本质上 XMLEncoder 与 XMLDecoder 也是一种序列化（编码）与反序列化（解码）的操作。
     * XMLDecoder在JDK 1.4~JDK 11中都存在反序列化漏洞安全风险。攻击者可以通过此漏洞远程执行恶意代码来入侵服务器。在项目中应禁止使用XMLDecoder方式解析XML内容
     * 在weblogic中多个包（wls-wast、wls9_async_response、_async）使用了该类
     */

    public static void main(String[] args) {
        HashMap<Object, Object> map = new HashMap<>();
        map.put("name", "zhangwei");
        map.put("age", new String[]{"a", "b", "c"});

        // XMLEncoder 生成的 XML 序列化文档表示对象
        XMLEncoder xmlEncoder = new XMLEncoder(System.out);
        xmlEncoder.writeObject(map);
        xmlEncoder.close();
    }


    @ApiOperation(value = "vul: XMLDecoder反序列化")
    @GetMapping("/vul")
    public void vul() {
        String path = "src/main/resources/payload/payload3.xml";
        File file = new File(path);
        FileInputStream fis = null;
        try {
            fis = new FileInputStream(file);
        } catch (Exception e) {
            e.printStackTrace();
        }

        BufferedInputStream bis = new BufferedInputStream(fis);
        XMLDecoder xmlDecoder = new XMLDecoder(bis);
        xmlDecoder.readObject();
        xmlDecoder.close();
    }
}
