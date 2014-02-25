/*
Based on
http://ttux.net/post/3des-java-encrypter-des-java-encryption/

modified for ePassLeser MAC DES Functions

*/

import java.security.MessageDigest;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Formatter;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.IvParameterSpec;


//import org.apache.commons.codec.binary.Base64;

public class MAC {
  private KeySpec keySpec;
  private SecretKey key;
  private IvParameterSpec iv;

    public static byte[] ConvertHexString(String data) {
      int s = data.length();
      int z = 0;
      byte[] b = new byte[s/2];
      for (int i = 0; i < s; i+=2) {
        b[z] = (byte) Integer.parseInt(data.substring(i, i+2),16);
        z++;

      }
      return b;
  }


  public static String ByteToHex(byte[] data) {
    Formatter formatter = new Formatter();
    for (byte b : data) {
      formatter.format("%02x", b);
    }
    String result = formatter.toString();
    formatter.close();
    return result;

  }

  public MAC(String keyString) {
    try {
      //final MessageDigest md = MessageDigest.getInstance("md5");
      //final byte[] digestOfPassword = md.digest(Base64.decodeBase64(keyString.getBytes("utf-8")));
      //final byte[] digestOfPassword = md.digest(keyString.getBytes("utf-8"));
      final byte[] keyBytes = Arrays.copyOf(ConvertHexString(keyString), 8);
      //for (int j = 0, k = 16; j < 8;) {
      //  keyBytes[k++] = keyBytes[j++];
      //}



      //System.out.println("KeyBytes: "+ByteToHex(keyBytes));

      keySpec = new DESKeySpec(keyBytes);

      //key = ConvertHexString(keyString);
      key = SecretKeyFactory.getInstance("DES").generateSecret(keySpec);

      //iv = new IvParameterSpec(ivString.getBytes());
      byte[] iv_tmp = {0,0,0,0,0,0,0,0};
      iv = new IvParameterSpec(iv_tmp);
    } catch(Exception e) {
      e.printStackTrace();
    }
  }

  public String encrypt(String value) {
    try {
      Cipher ecipher = Cipher.getInstance("DES/CBC/NoPadding","SunJCE");
      ecipher.init(Cipher.ENCRYPT_MODE, key, iv);

      if(value==null)
        return null;

      // Encode the string into bytes using utf-8
      //byte[] utf8 = value.getBytes("UTF-8");

      byte[] utf8 = ConvertHexString(value);

      // Encrypt
      byte[] enc = ecipher.doFinal(utf8);

      // Encode bytes to base64 to get a string
      //return new String(Base64.encodeBase64(enc),"UTF-8");

      //return new String(enc,"UTF-8");

      return ByteToHex(enc);
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }

  public String decrypt(String value) {
    try {
      Cipher dcipher = Cipher.getInstance("DES/CBC/NoPadding","SunJCE");
      dcipher.init(Cipher.DECRYPT_MODE, key, iv);

      if(value==null)
        return null;

      // Decode base64 to get bytes
      //byte[] dec = Base64.decodeBase64(value.getBytes());
      byte[] dec = ConvertHexString(value);

      // Decrypt
      byte[] utf8 = dcipher.doFinal(dec);

      return ByteToHex(utf8);

      // Decode using utf-8
      //return new String(utf8, "UTF8");
    } catch (Exception e) {
      e.printStackTrace();
    }
    return null;
  }
}
