package org.owasp.webwolf.jwt;

import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.servlet.ModelAndView;

import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED_VALUE;
import static org.springframework.http.MediaType.APPLICATION_JSON_VALUE;

@RestController
public class JWTController {

    @GetMapping("/WebWolf/jwt")
    public ModelAndView jwt() {
        return new ModelAndView("jwt");
    }

    @PostMapping(value = "/WebWolf/jwt/decode", consumes = APPLICATION_FORM_URLENCODED_VALUE, produces = APPLICATION_JSON_VALUE)
    public JWTToken decode(@RequestBody MultiValueMap<String, String> formData) {
        var jwt = formData.getFirst("token");
        var secretKey = formData.getFirst("secretKey");
        return JWTToken.decode(jwt, secretKey);
    }

    @PostMapping(value = "/WebWolf/jwt/encode", consumes = APPLICATION_FORM_URLENCODED_VALUE, produces = APPLICATION_JSON_VALUE)
    public JWTToken encode(@RequestBody MultiValueMap<String, String> formData) {
        var header = formData.getFirst("header");
        var payload = formData.getFirst("payload");
        var secretKey = formData.getFirst("secretKey");
        return JWTToken.encode(header, payload, secretKey);
    }

}
