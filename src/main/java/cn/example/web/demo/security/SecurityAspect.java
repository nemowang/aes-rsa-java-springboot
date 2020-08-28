package cn.example.web.demo.security;

import cn.example.web.demo.annotation.Decrypt;
import cn.example.web.demo.annotation.Encrypt;
import cn.example.web.demo.utils.AESUtil;
import cn.example.web.demo.utils.RSA;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.commons.lang3.StringUtils;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.aspectj.lang.annotation.Pointcut;
import org.aspectj.lang.reflect.MethodSignature;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.servlet.http.HttpServletRequest;
import java.lang.annotation.Annotation;
import java.lang.reflect.Method;
import java.security.interfaces.RSAPrivateKey;
import java.text.SimpleDateFormat;
import java.util.Base64;

@Aspect
@Component
public class SecurityAspect {

    /**
     * Pointcut 切入点
     * 匹配com.nemo.consumer.controller包下面的所有方法
     */
    @Pointcut(value = "execution(public * cn.example.web.demo.controller.*.*(..))")
    public void securityAspect() {
    }

    @Autowired
    private AESUtil aesUtil;

    @Autowired
    private RSA rsa;

    /**
     * 环绕通知
     */
    @Around(value = "securityAspect()")
    public Object around(ProceedingJoinPoint pjp) {
        try {
            ServletRequestAttributes attributes = (ServletRequestAttributes) RequestContextHolder.getRequestAttributes();
            assert attributes != null;
            //request对象
            HttpServletRequest request = attributes.getRequest();

            //http请求方法  post get
            String httpMethod = request.getMethod().toLowerCase();

            //method方法
            Method method = ((MethodSignature) pjp.getSignature()).getMethod();

            //method方法上面的注解
            Annotation[] annotations = method.getAnnotations();

            //方法的形参参数
            Object[] args = pjp.getArgs();

            //是否有@Decrypt
            boolean hasDecrypt = false;
            //是否有@Encrypt
            boolean hasEncrypt = false;
            for (Annotation annotation : annotations) {
                if (annotation.annotationType() == Decrypt.class) {
                    hasDecrypt = true;
                }
                if (annotation.annotationType() == Encrypt.class) {
                    hasEncrypt = true;
                }
            }

            //前端公钥
            String publicKey = null;

            // AES密钥
            String aesKey = StringUtils.EMPTY;

            //jackson
            ObjectMapper mapper = new ObjectMapper();
            //jackson 序列化和反序列化 date处理
            mapper.setDateFormat( new SimpleDateFormat("yyyy-MM-dd HH:mm:ss"));

            //执行方法之前解密，且只拦截post请求
            if ("post".equals(httpMethod) && hasDecrypt) {

                //AES加密后的数据
                String data = request.getParameter("data");
                //后端RSA公钥加密后的AES的key
                aesKey = request.getParameter("aesKey");
                /*//前端公钥
                publicKey = request.getParameter("publicKey");
                System.out.println("前端公钥：" + publicKey);*/

                RSAPrivateKey rsaPrivateKey = rsa.loadPrivateKeyByFile("../keys/privateKey.pem");
                //后端私钥解密的到AES的key
                byte[] plaintext = rsa.decrypt(rsaPrivateKey, Base64.getDecoder().decode(aesKey));
                aesKey = new String(plaintext);
                System.out.println("解密出来的AES的key：" + aesKey);

                //RSA解密出来字符串多一对双引号
                //aesKey = aesKey.substring(1, aesKey.length() - 1);

                //AES解密得到明文data数据

                String decrypt = aesUtil.decrypt(data, aesKey);
                System.out.println("解密出来的data数据：" + decrypt);

                //设置到方法的形参中，目前只能设置只有一个参数的情况
                mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

                if(args.length > 0){
                    args[0] = mapper.readValue(decrypt, args[0].getClass());
                }
            }

            //执行并替换最新形参参数   PS：这里有一个需要注意的地方，method方法必须是要public修饰的才能设置值，private的设置不了
            Object o = pjp.proceed(args);

            //返回结果之前加密
            if (hasEncrypt) {
                mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
                /*//每次响应使用入参的AES密钥，如果入参没有密钥就随机生成AES密钥，加密data数据
                String key = StringUtils.EMPTY;
                if (StringUtils.isNotEmpty(aesKey)) {
                    // 使用入参的AES密钥
                    key = aesKey;
                } else {
                    // 随机生成AES密钥
                    key = aesUtil.genarateRandomKey();
                }*/
                // 每次响应使用入参的AES密钥加密data数据
                String key = StringUtils.EMPTY;
                if (StringUtils.isNotEmpty(aesKey)) {
                    // 使用入参的AES密钥
                    key = aesKey;
                }
                System.out.println("AES的key：" + key);
                String dataString = mapper.writeValueAsString(o);
                System.out.println("需要加密的data数据：" + dataString);
                String data = aesUtil.encrypt(dataString, key);

                //转json字符串并转成Object对象，设置到Result中并赋值给返回值o
                // o = Result.of(mapper.readValue("{\"data\":\"" + data + "\",\"aesKey\":\"" + aesKey + "\"}", Object.class));
                o = data;
            }

            //返回
            return o;

        } catch (Throwable e) {
            System.err.println(pjp.getSignature());
            e.printStackTrace();
            return "加解密异常：" + e.getMessage();
        }
    }
}
