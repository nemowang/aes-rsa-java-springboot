package cn.example.web.demo.utils;

import cn.hutool.core.codec.Base64;
import cn.hutool.core.util.HexUtil;
import cn.hutool.core.util.StrUtil;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * @author ：lijing
 * @date ：Created in 2020/8/5 0:13
 * @description：
 */
@Component
public class AESUtil {

    /**
     * 加密算法AES
     */
    private static final String KEY_ALGORITHM = "AES";

    /**
     * 算法名称/加密模式/数据填充方式
     * AES/CBC/PKCS5Padding
     */
    private static final String ALGORITHMS = "AES/CBC/PKCS5Padding";

    /**
     * 随机生成AES密钥
     * @return AES密钥
     */
    public String genarateRandomKey() {
        KeyGenerator keygen = null;
        try {
            keygen = KeyGenerator.getInstance(KEY_ALGORITHM);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(" genarateRandomKey fail!", e);
        }
        SecureRandom random = new SecureRandom();
        keygen.init(random);
        Key key = keygen.generateKey();
        return Base64.encode(key.getEncoded());
    }

    /**
     * 解密
     * @param encryptStr 密文
     * @param key 密钥
     * @return 解密得到的原文
     */
    public String decrypt(String encryptStr, String key) {
        String result = StringUtils.EMPTY;
        try {
            byte[] keyBytes = Base64.decode(key);
            byte[] dataBytes = HexUtil.decodeHex((encryptStr.toCharArray()));
            byte[] resultBytes = this.AES_CBC_Decrypt(dataBytes, keyBytes, keyBytes);
            result = new String(resultBytes);
            return result;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return result;
    }

    /**
     * 加密
     * @param content 待加密原文
     * @param key 密钥
     * @return 加密得到的密文
     */
    public String encrypt(String content, String key) {
        String enc = StringUtils.EMPTY;
        try {
            byte[] keyBytes = Base64.decode(key);
            byte[] dataBytes = StrUtil.bytes(content, StandardCharsets.UTF_8);
            byte[] resultBytes = this.AES_CBC_Encrypt(dataBytes, keyBytes, keyBytes);
            // enc = new String(resultBytes);
            enc = HexUtil.encodeHexStr(resultBytes);
            return enc;
        } catch (Exception e) {
            e.printStackTrace();
        }
        return enc;
    }


    private byte[] AES_CBC_Decrypt(byte[] data, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = getCipher(Cipher.DECRYPT_MODE, key, iv);
        return cipher.doFinal(data);
    }

    private byte[] AES_CBC_Encrypt(byte[] data, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, key, iv);
        return cipher.doFinal(data);
    }


    private Cipher getCipher(int mode, byte[] key, byte[] iv) throws Exception {
        Cipher cipher = Cipher.getInstance(ALGORITHMS);
        //因为AES的加密块大小是128bit(16byte), 所以key是128、192、256bit无关
        //System.out.println("cipher.getBlockSize()： " + cipher.getBlockSize());
        SecretKeySpec secretKeySpec = new SecretKeySpec(key, KEY_ALGORITHM);
        cipher.init(mode, secretKeySpec, new IvParameterSpec(iv));

        return cipher;
    }

}
