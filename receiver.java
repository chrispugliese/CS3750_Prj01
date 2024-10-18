import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Scanner;


public class receiver {
    
    public static void main(String[] args){
        try {

            //read information on the designated keys to be used from the key files and generate ysecretkey and sym key
            PrivateKey yPrivateKey = loadPrivateKey("YPrivate.key");
            SecretKey aesKey = loadAESKey("symmetric.key");

            // get the input from the user to get the name of the message file 
            Scanner scanner = new Scanner(System.in);
            System.out.print("Input the name of the message file: ");
            String outputFileName = scanner.nextLine();
            scanner.close();
            
            // we need to decrypt the RSA-encrypted data in message.rsacipher
            byte[] rsaCiphertext = Files.readAllBytes(Paths.get("message.rsacipher"));
            byte[] rsaDecryptedData = rsaDecryptBlockByBlock(yPrivateKey, rsaCiphertext);

            //then save the decrypted data to message.add-msg
            saveToFile("message.add-msg", rsaDecryptedData);

            //calculate AES Encryption of SHA265(M) using the secret key
            byte[] aesEncryptedDigest = new byte[32];
            byte[] message = new byte[rsaDecryptedData.length - 32];
            System.arraycopy(rsaDecryptedData, 0, aesEncryptedDigest, 0, 32);
            System.arraycopy(rsaDecryptedData, 32, message, 0, message.length);

            saveToFile(outputFileName, message);

            byte[] decryptedDigest = aesDecrypt(aesKey, aesEncryptedDigest);
            saveToFile("message.dd", decryptedDigest);
            System.out.println("Decrypted SHA-256 Digest (Hex): " + bytesToHex(decryptedDigest));

            byte[] calculateDigest = calculateSHA256Digest(message);
            System.out.println("Calculated SHA-256 Digest (Hex): " + bytesToHex(calculateDigest));

            //we need to compare each digest 
            if(MessageDigest.isEqual(decryptedDigest, calculateDigest)){
                System.out.println("Message integrity check PASSED");
            }else{
                System.out.println("Message integrity check FAILED");
            }




        } catch (Exception e){
            e.printStackTrace();
        }
    }
    //load rsa private key
    private static PrivateKey loadPrivateKey(String filename) throws Exception{
        try (ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(filename))){
            BigInteger modulus = (BigInteger) objectInputStream.readObject();
            BigInteger exponent = (BigInteger) objectInputStream.readObject();
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec((modulus), exponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePrivate(keySpec);
        }
    }
    //load aes symmetric key
    private static SecretKey loadAESKey(String filename) throws IOException{
        String keyString = new String(Files.readAllBytes(Paths.get(filename)), "UTF-8");
        byte[] keyBytes = keyString.getBytes("UTF-8");
        return new SecretKeySpec(keyBytes, "AES");
    }

    private static void saveToFile(String filename, byte[] data) throws IOException{
        try (FileOutputStream fileOutputStream = new FileOutputStream(filename)){
            fileOutputStream.write(data);

        }
    }

    private static byte[] rsaDecryptBlockByBlock(PrivateKey key, byte[] data) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);

        ByteArrayOutputStream decryptedData = new ByteArrayOutputStream();
        int blockSize = 128;

        for (int i=0; i<data.length; i += blockSize) {
            int length = Math.min(blockSize, data.length - i);
            byte[] block = cipher.doFinal(data, i, length);
            decryptedData.write(block);

        }

        return decryptedData.toByteArray();


    
    }

    private static byte[] calculateSHA256Digest(byte[] message) throws NoSuchAlgorithmException{
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(message);
    }

    private static byte[] aesDecrypt(SecretKey key, byte[] data) throws Exception{
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        return cipher.doFinal(data);

    }

    // we need a method for bytes to hex 
    private static String bytesToHex(byte[] bytes) {
        StringBuilder stringBuilder = new StringBuilder();
        for (byte b : bytes ){
            stringBuilder.append(String.format("%02x", b));
        }
        return stringBuilder.toString();
    

    }
}
