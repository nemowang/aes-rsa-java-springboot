package cn.example.web.demo.utils;

import cn.example.web.demo.DemoApplication;
import cn.hutool.core.codec.Base64;
import lombok.extern.slf4j.Slf4j;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

@Slf4j
@RunWith(SpringRunner.class)
@SpringBootTest(classes = DemoApplication.class)
public class AESTest {

    private static final String aesKey = "AAAAAAAAAA0AAL8AAOgAuA==";

    @Autowired
    private AESUtil aesUtil;

    @Test
    public void decryptTest() {
        String encryptStr = "263346164b80e59948a1ac4a633bca3f6a5e644f8d1d51d587f109162d3a89ad";
        String key = "AAAAAAAAAA0AAL8AAOgAuA==";
        String decrypt = aesUtil.decrypt(encryptStr, key);
        System.out.println(decrypt);
    }

    @Test
    public void encryptTest() {
        String str = "hello from server side";
        String encrypt = aesUtil.encrypt(str, aesKey);
        System.out.println(encrypt);
    }

    @Test
    public void generateRandomKeyTest() {
        String key = aesUtil.genarateRandomKey();
        System.out.println(key);
    }
}
