package cn.example.web.demo.controller;

import cn.example.web.demo.annotation.Decrypt;
import cn.example.web.demo.annotation.Encrypt;
import cn.example.web.demo.domain.DecryptTestReqVO;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

/**
 * 参数加解密测试Controller
 */
@Slf4j
@RestController
@RequestMapping("/test")
public class TestController {

    /**
     * 入参解密
     * @param reqVO
     * @return
     */
    @Decrypt
    @PostMapping("decrypt-Test")
    public String decryptTest(DecryptTestReqVO reqVO) {
        log.info("name={}", reqVO.getName());
        return "my name is " + reqVO.getName();
    }

    /**
     * 出参加密
     * @param reqVO
     * @return
     */
    @Encrypt
    @PostMapping("encrypt-Test")
    public String encryptTest(@RequestBody DecryptTestReqVO reqVO) {
        log.info("name={}", reqVO.getName());
        return "my name is " + reqVO.getName();
    }

    /**
     * 入参解密，出参加密
     * @param reqVO
     * @return
     */
    @Decrypt
    @Encrypt
    @PostMapping("decrypt-encrypt-Test")
    public String decryptEncryptTest(DecryptTestReqVO reqVO) {
        log.info("name={}", reqVO.getName());
        return "my name is " + reqVO.getName();
    }
}
