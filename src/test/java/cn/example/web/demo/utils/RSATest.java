package cn.example.web.demo.utils;

import cn.example.web.demo.DemoApplication;
import lombok.extern.slf4j.Slf4j;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.junit4.SpringRunner;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;

@Slf4j
@RunWith(SpringRunner.class)
@SpringBootTest(classes = DemoApplication.class)
public class RSATest {

    @Autowired
    private RSA rsa;

    @Test
    public void rsaTest() throws Exception {
        String data = "aaabbbcccdddeeefff";

        // rsa.genKeyPair("keys/");

//        File pkcs8_rsa_private_key = new File("keys/pkcs8_rsa_private_key.pem");
//        Assert.assertTrue(pkcs8_rsa_private_key.exists());
//
//        File rsa_public_key = new File("keys/rsa_public_key.pem");
//        Assert.assertTrue(rsa_public_key.exists());
//
//        RSA.INSTANCE.genKeyPair("keys/", "publicKey.pem", "privateKey.pem");
//
//        File publicKey = new File("keys/publicKey.pem");
//        Assert.assertTrue(publicKey.exists());
//
//        File privateKey = new File("keys/privateKey.pem");
//        Assert.assertTrue(privateKey.exists());
//
//        RSAPublicKey rsaPublicKey = RSA.INSTANCE.loadPublicKeyByFile("keys/publicKey.pem");
//        byte[] encryptedData = RSA.INSTANCE.encrypt(rsaPublicKey, data.getBytes());
//        RSAPrivateKey rsaPrivateKey = RSA.INSTANCE.loadPrivateKeyByFile("keys/privateKey.pem");
//
//        byte[] decryptedData = RSA.INSTANCE.decrypt(rsaPrivateKey, encryptedData);
//
//        Assert.assertEquals(data, new String(decryptedData));



        RSAPublicKey rsaPublicKey = rsa.loadPublicKeyByFile("keys/publicKey.pem");
        RSAPrivateKey rsaPrivateKey = rsa.loadPrivateKeyByFile("keys/privateKey.pem");

        byte[] decryptedData = rsa.decrypt(rsaPrivateKey, Base64.getDecoder().decode("P4/i+rAYyfCoufmytTl2otnIlE9sdggEm4hbwAvmSxzZ/vo2vxTGCY+atfdn3rD3WvTx+ftiv5H3cJecIx27S+C7/PB5u1ud6KllRtmbSWtHjNh7naXoNBGpTvtteTfxUUqvLx2uaPlTmz6XFiV3GV4dgWT6X0ACtMKgWtyJHa85fP2AMQiXWw4M0eK+b9kOs8LpZaZg6vAjOG7xF90hE302t0OtqHMT1b9TUq/hyiEvwLfem4DE/GFipNb7UoLErc0PcLFaaWZoudigliaCsGl7NNgPQK3JmioERYNoWGa/TbZePBAZdx8bVQt1uAlVO4eCzo3X0AnCAwN8IOCApA=="));
        System.out.println(new String(decryptedData));
    }
}
