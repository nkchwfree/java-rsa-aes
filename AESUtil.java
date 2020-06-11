import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;


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
     *
     * @param filename
     * @return
     * @throws IOException
     */
    public static void encryptFile(String filename, String outfilename, String key, String iv) throws IOException{
        File f = new File(filename);
        if(!f.exists()) {
            throw new FileNotFoundException(filename);
        }

        File outputFile = new File(outfilename);
        FileOutputStream outputFileStream = null;

        // try to open file output.txt
        try {
            outputFileStream = new FileOutputStream(outputFile);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        BufferedInputStream in = null;
        try{
            in = new BufferedInputStream(new FileInputStream(f));
            int buf_size = 1024*1024-1;
            byte[] buffer = new byte[buf_size];
            int len = 0;
            while(-1 != (len = in.read(buffer,0,buf_size))){
                byte[] ss = AESUtil.subBytes(buffer,0,len);
                outputFileStream.write(AESUtil.encrypt(ss, key, iv));
            }
            outputFileStream.close();
        }catch (IOException e) {
            e.printStackTrace();
            throw e;
        }finally{
            try{
                in.close();
            }catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    /**
     *
     * @param filename
     * @return
     * @throws IOException
     */
    public static void decryptFile(String filename, String outfilename, String key, String iv) throws IOException{
        File f = new File(filename);
        if(!f.exists()){
            throw new FileNotFoundException(filename);
        }

        File outputFile = new File(outfilename);
        FileOutputStream outputFileStream = null;

        // try to open file output.txt
        try {
            outputFileStream = new FileOutputStream(outputFile);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        }

        BufferedInputStream in = null;
        try{
            in = new BufferedInputStream(new FileInputStream(f));
            int buf_size = 1024*1024;
            byte[] buffer = new byte[buf_size];
            int len = 0;
            while(-1 != (len = in.read(buffer,0,buf_size))){
                byte[] ss = AESUtil.subBytes(buffer,0,len);
                outputFileStream.write(AESUtil.decrypt(ss, key, iv));
            }
            outputFileStream.close();
        }catch (IOException e) {
            e.printStackTrace();
            throw e;
        }finally{
            try{
                in.close();
            }catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public static void compressFile(String filename, String outfilename) throws Exception {
        File f = new File(filename);
        if(!f.exists()){
            throw new FileNotFoundException(filename);
        }

        File outputFile = new File(outfilename);
        GZIPOutputStream os = new GZIPOutputStream(new FileOutputStream(outputFile));
        BufferedInputStream is = new BufferedInputStream(new FileInputStream(f));

        int count;
        int buf_size = 1024*1024;
        byte data[] = new byte[buf_size];
        while ((count = is.read(data, 0, buf_size)) != -1) {
            os.write(data, 0, count);
        }

        os.finish();
        os.flush();
        os.close();
        is.close();
    }

    public static void decompressFile(String filename, String outfilename) throws Exception {
        File f = new File(filename);
        if(!f.exists()){
            throw new FileNotFoundException(filename);
        }

        GZIPInputStream gis = new GZIPInputStream(new FileInputStream(f));
        FileOutputStream os = new FileOutputStream(new File(outfilename));

        int count;
        int buf_size = 1024*1024;
        byte data[] = new byte[buf_size];
        while ((count = gis.read(data, 0, buf_size)) != -1) {
            os.write(data, 0, count);
        }

        gis.close();

        //os.finish();
        os.flush();
        os.close();
        gis.close();
    }

    public static byte[] subBytes(byte[] src, int begin, int count) {
        byte[] bs = new byte[count];
        System.arraycopy(src, begin, bs, 0, count);
        return bs;
    }

    public static void main(String[] args) {
        String content = "12345678901234567890中国=o=人";
        String key = "12345678abcdefgh";
        String iv = "0123456789876543";
        System.out.println("明文:" + content+"\n\n");

        try {
            // AES 加密字符串
            byte[] ss = AESUtil.encrypt(content.getBytes("UTF-8"), key, iv);

            System.out.println("解密后内容：");
            System.out.println(new String(AESUtil.decrypt(ss, key, iv)));

            //AES 对文件进行加密
            AESUtil.encryptFile("new.txt", "2.dat", key, iv);
            //AES 对文件进行解密
            AESUtil.decryptFile("2.dat", "new2.txt", key, iv);

            //压缩文件
            AESUtil.compressFile("new.txt", "new.txt.gz");
            //解压文件
            AESUtil.decompressFile("new.txt.gz", "new.txt.decompress");
        }
        catch(Exception ex) {

        }
    }
}