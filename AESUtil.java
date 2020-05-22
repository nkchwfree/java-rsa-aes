import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;



public class AESUtil{
    private static final String KEY_ALGORITHM = "AES";
    private static final String DEFAULT_CIPHER_ALGORITHM = "AES/CBC/PKCS5Padding";//默认的加密算法

    /**
     * AES 加密操作
     *
     * @param content 待加密内容
     * @param key 加密密钥
     * @return 返回Base64转码后的加密数据
     */
    public static byte[] encrypt(byte[] content, String key, String iv) {
        try {
            Cipher cipher = getCipher(Cipher.ENCRYPT_MODE, key, iv);

            return cipher.doFinal(content);// 加密
        } catch (Exception ex) {
            Logger.getLogger(AESUtil.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }

    /**
     * AES 解密操作
     *
     * @param content
     * @param key
     * @return
     */
    public static byte[] decrypt(byte[] content, String key, String iv) {

        try {
            //实例化
            Cipher cipher = getCipher(Cipher.DECRYPT_MODE, key, iv);

            //final Base64.Decoder decoder = Base64.getDecoder();

            //System.out.println("content-length="+content.getBytes("iso-8859-1").length);

            //执行操作
            //byte[] result = cipher.doFinal(decoder.decode(content));
            return cipher.doFinal(content);
        } catch (Exception ex) {
            Logger.getLogger(AESUtil.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }

    private static Cipher getCipher(int mode, String key, String iv) {
        try {
            //实例化
            Cipher cipher = Cipher.getInstance(DEFAULT_CIPHER_ALGORITHM);

            IvParameterSpec ivps = new IvParameterSpec(iv.getBytes());//使用CBC模式，需要一个向量iv，可增加加密算法的强度
            SecretKeySpec sks = new SecretKeySpec(key.getBytes(), KEY_ALGORITHM);

            //使用密钥初始化，设置为解密模式
            cipher.init(mode, sks, ivps);

            return cipher;
        } catch (Exception ex) {
            Logger.getLogger(AESUtil.class.getName()).log(Level.SEVERE, null, ex);
        }

        return null;
    }

    public static void writeFile(String filename, byte[] content) {
        File outputFile = new File(filename);
        FileOutputStream outputFileStream = null;

        // try to open file output.txt
        try {
            outputFileStream = new FileOutputStream(outputFile);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        try {
            outputFileStream.write(content);
            outputFileStream.close();
        } catch (IOException e1) {
            e1.printStackTrace();
        }
    }

    /**
     * 生成加密秘钥
     *
     * @return
     */
    private static SecretKeySpec getSecretKey(final String key) {
        return new SecretKeySpec(key.getBytes(), KEY_ALGORITHM);// 转换为AES专用密钥
    }

    public static void main(String[] args) {
        // try {

        //     final Base64.Encoder encoder = Base64.getEncoder();
        //     final String text = "字串文字";
        //     final byte[] textByte = text.getBytes("UTF-8");
        //     //編碼
        //     final String encodedText = encoder.encodeToString(textByte);
        //     System.out.println(encodedText);

        //     //解碼
        //     final Base64.Decoder decoder = Base64.getDecoder();
        //     System.out.println(new String(decoder.decode(encodedText), "UTF-8"));
        // }
        // catch(Exception e) {
        //     System.out.println("exc");
        // }

        String content = "12345678901234567890中国=o=人";
        String key = "12345678abcdefgh";
        String iv = "0123456789876543";
        //System.out.println("content:" + content);


        // String s1 = AESUtil.encrypt(content, key, iv);
        // System.out.println("s1:" + s1);
        // System.out.println(s1.length());
        // System.out.println("s2:"+AESUtil.decrypt(s1, key, iv));

        //byte[] ss = "abc".getBytes();

        //final Base64.Encoder encoder = Base64.getEncoder();
        //編碼
        //System.out.println(encoder.encodeToString(ss));
        try {
            byte[] ss = AESUtil.encrypt(content.getBytes("UTF-8"), key, iv);
            //System.out.println(new String(ss, "UTF-8"));
            //System.out.println(new String(ss, "iso-8859-1"));
            AESUtil.writeFile("1.dat", ss);
        }
        catch(Exception ex) {

        }
    }

}