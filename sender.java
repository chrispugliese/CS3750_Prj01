import java.io.*;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Scanner;
import java.util.Arrays;

public class sender {

    public static void main(String[] args){
        try {

            // loading public y key
            PublicKey yPublicKey = loadPublicKey("YPublic.key");
            // loading symmetric key
            SecretKey aesKey = loadAESKey("symmetric.key");

            // now we need to prompt the user to provide the name of the file containing the message M
            Scanner scanner = new Scanner(System.in);
            System.out.print("Input the name of the message file: ");
            String messageFileName = scanner.nextLine();

            // read the message and use function 'calculateSHA256Digest'
            byte[] message = Files.readAllBytes(Paths.get(messageFileName));
            byte[] messageDigest = calculateSHA256Digest(message);
            saveToFile("message.dd", messageDigest);
            System.out.println("SHA-256 Digest (Hex): " + bytesToHex(messageDigest));

            // Now we need to ask the user if they want to invert the 1st byte in SHA256(M)
            System.out.print("Do you want to invert the first byte in SHA256(M)? (Y or N): ");
            String invertChoice = scanner.nextLine();
            if (invertChoice.equalsIgnoreCase("Y")){
                messageDigest[0] = (byte) ~messageDigest[0];
            }
            saveToFile("message.dd", messageDigest);
        
	    byte[] aesEncryptedDigest = aesEncrypt(aesKey, messageDigest); // Use full 32-byte digest
            saveToFile("message.add-msg", aesEncryptedDigest);

            //Now we need to append the message M read from the file asked from the user
            try (FileOutputStream fileOutputStream = new FileOutputStream("message.add-msg", true)){
                fileOutputStream.write(message);
            }

            // now we need to encrypt the combined data with RSA
            byte[] rsaEncryptedMessage = rsaEncrypt(yPublicKey, Files.readAllBytes(Paths.get("message.add-msg")));
            saveToFile("message.rsacipher", rsaEncryptedMessage);

            System.out.println("Message encrypted and save to message.rsacipher.");

            scanner.close();

        } catch (Exception e){
            e.printStackTrace();

        

        }
    }

    // function to load the y public key
    private static PublicKey loadPublicKey(String filename) throws Exception {
        try (ObjectInputStream objectInputStream = new ObjectInputStream(new FileInputStream(filename))){
            BigInteger modulus = (BigInteger) objectInputStream.readObject();
            BigInteger exponent = (BigInteger) objectInputStream.readObject();
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            return keyFactory.generatePublic(keySpec);

        }
    }

    //function to load the symmetric key
    private static SecretKey loadAESKey(String filename) throws IOException{

        String keyString = new String(Files.readAllBytes(Paths.get(filename)), "UTF-8");
        byte[] keyBytes = keyString.getBytes("UTF-8");
        return new SecretKeySpec(keyBytes, "AES");
    }

    //function to calculate the digest of a message (SHA-256)
    private static byte[] calculateSHA256Digest(byte[] message) throws NoSuchAlgorithmException{
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(message);
    }

    //function to encrypt data with AES
    private static byte[] aesEncrypt(SecretKey key, byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
	cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }

    //encrypt with padding
    private static byte[] rsaEncrypt(PublicKey key, byte[] data) throws Exception{
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, key);

	ByteArrayOutputStream encryptedData = new ByteArrayOutputStream();
	int blockSize = 117;

	for (int i = 0; i < data.length; i += blockSize){
		int length = Math.min(blockSize, data.length - i);
		byte[] block = cipher.doFinal(data, i, length);
		encryptedData.write(block);
		}

        return encryptedData.toByteArray();

    }

    // save byte data to file
    private static void saveToFile(String filename, byte[] data) throws IOException{
        try (FileOutputStream fileOutputStream = new FileOutputStream(filename)){
            fileOutputStream.write(data);
        }
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
// use 1024 key
