/**
 * rsa_public_key.pem RSA公钥文件
 * rsa_private_key_pkcs8.pem RSA私钥文件
 *
 */

import javax.crypto.Cipher;
import java.io.ByteArrayOutputStream;
import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

import java.util.Base64;
import java.io.FileReader;
import java.io.BufferedReader;


public class RSAUtils {
    public static final String CHARSET = "UTF-8";
    public static final String RSA_ALGORITHM = "RSA";

    /**
     * 得到公钥
     * @param publicKey  密钥字符串（经过base64编码）
     * @throws Exception
     */
    public static RSAPublicKey getPublicKeyFromPem() throws Exception {
        BufferedReader br = new BufferedReader(new FileReader("./rsa_public_key.pem"));
        String s = br.readLine();
        String str = "";
        s = br.readLine();
        while (s.charAt(0) != '-') {
            str += s;
            s = br.readLine();
        }

        byte[] b = base64Decode(str);
        KeyFactory kf = KeyFactory.getInstance("RSA");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(b);
        RSAPublicKey pubKey = (RSAPublicKey)kf.generatePublic(keySpec);
        return pubKey;
    }

    /**
     * 得到私钥
     * @param privateKey  密钥字符串（经过base64编码）
     * @throws Exception
     */
    public static RSAPrivateKey getPrivateKeyFromPem() throws Exception {
        BufferedReader br = new BufferedReader(new FileReader("./rsa_private_key_pkcs8.pem"));
        String s = br.readLine();
        String str = "";
        s = br.readLine();
        while (s.charAt(0) != '-') {
            str += s;
            s = br.readLine();
        }
        byte[] b = base64Decode(str);

        // 生成私匙
        KeyFactory kf = KeyFactory.getInstance("RSA");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(b);
        RSAPrivateKey privateKey = (RSAPrivateKey)kf.generatePrivate(keySpec);
        return privateKey;
    }

    /**
     * 公钥加密
     * @param data
     * @param publicKey
     * @return
     */
    public static String publicEncrypt(String data, RSAPublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);

            return RSAUtils.base64EncodeString(rsaSplitCodec(cipher, Cipher.ENCRYPT_MODE, data.getBytes(CHARSET), publicKey.getModulus().bitLength()));
        } catch (Exception e) {
            throw new RuntimeException("加密字符串[" + data + "]时遇到异常", e);
        }
    }

    /**
     * 私钥解密
     * @param data
     * @param privateKey
     * @return
     */

    public static String privateDecrypt(String data, RSAPrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            return new String(rsaSplitCodec(cipher, Cipher.DECRYPT_MODE, RSAUtils.base64Decode(data), privateKey.getModulus().bitLength()), CHARSET);
        } catch (Exception e) {
            throw new RuntimeException("解密字符串[" + data + "]时遇到异常", e);
        }
    }

    /**
     * 私钥加密
     * @param data
     * @param privateKey
     * @return
     */

    public static String privateEncrypt(String data, RSAPrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            //每个Cipher初始化方法使用一个模式参数opmod，并用此模式初始化Cipher对象。此外还有其他参数，包括密钥key、包含密钥的证书certificate、算法参数params和随机源random。
            cipher.init(Cipher.ENCRYPT_MODE, privateKey);
            return RSAUtils.base64EncodeString(rsaSplitCodec(cipher, Cipher.ENCRYPT_MODE, data.getBytes(CHARSET), privateKey.getModulus().bitLength()));
        } catch (Exception e) {
            throw new RuntimeException("加密字符串[" + data + "]时遇到异常", e);
        }
    }

    /**
     * 公钥解密
     * @param data
     * @param publicKey
     * @return
     */

    public static String publicDecrypt(String data, RSAPublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance(RSA_ALGORITHM);
            cipher.init(Cipher.DECRYPT_MODE, publicKey);
            return new String(rsaSplitCodec(cipher, Cipher.DECRYPT_MODE, RSAUtils.base64Decode(data), publicKey.getModulus().bitLength()), CHARSET);
        } catch (Exception e) {
            throw new RuntimeException("解密字符串[" + data + "]时遇到异常", e);
        }
    }

    //rsa切割解码  , ENCRYPT_MODE,加密数据   ,DECRYPT_MODE,解密数据
    private static byte[] rsaSplitCodec(Cipher cipher, int opmode, byte[] datas, int keySize) {
        int maxBlock = 0;  //最大块
        if (opmode == Cipher.DECRYPT_MODE) {
            maxBlock = keySize / 8;
        } else {
            maxBlock = keySize / 8 - 11;
        }
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int offSet = 0;
        byte[] buff;
        int i = 0;
        try {
            while (datas.length > offSet) {
                if (datas.length - offSet > maxBlock) {
                    //可以调用以下的doFinal（）方法完成加密或解密数据：
                    buff = cipher.doFinal(datas, offSet, maxBlock);
                } else {
                    buff = cipher.doFinal(datas, offSet, datas.length - offSet);
                }
                out.write(buff, 0, buff.length);
                i++;
                offSet = i * maxBlock;
            }
        } catch (Exception e) {
            throw new RuntimeException("加解密阀值为[" + maxBlock + "]的数据时发生异常", e);
        }
        byte[] resultDatas = out.toByteArray();

        try {
            out.close();
        }
        catch(Exception e) {

        }
        return resultDatas;
    }

    private static String base64EncodeString(byte[] data) {
        final Base64.Encoder encoder = Base64.getEncoder();
        return encoder.encodeToString(data);
    }

    private static byte[] base64Decode(String data) {
        final Base64.Decoder decoder = Base64.getDecoder();
        return decoder.decode(data.getBytes());
    }

    public static void main(String[] args) throws Exception {
        String str = "123456";
        System.out.println("明文：\n" + str+"\n");

        System.out.println("公钥加密——私钥解密");
        String encodedData = RSAUtils.publicEncrypt(str, RSAUtils.getPublicKeyFromPem());  //传入明文和公钥加密,得到密文
        System.out.println("密文：\n" + encodedData);
        String decodedData = RSAUtils.privateDecrypt(encodedData, RSAUtils.getPrivateKeyFromPem()); //传入密文和私钥,得到明文
        System.out.println("解密后文字: \n" + decodedData+"\n");

        System.out.println("私钥加密——公钥解密");
        encodedData = RSAUtils.privateEncrypt(str, RSAUtils.getPrivateKeyFromPem());  //传入明文和公钥加密,得到密文
        System.out.println("密文：\n" + encodedData);
        decodedData = RSAUtils.publicDecrypt(encodedData, RSAUtils.getPublicKeyFromPem()); //传入密文和私钥,得到明文
        System.out.println("解密后文字: \n" + decodedData);
    }

}