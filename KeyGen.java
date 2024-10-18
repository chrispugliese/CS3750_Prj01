import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.util.Scanner;


public class KeyGen{
    public static void main(String[] args) throws Exception{

        /*  we need to create a function called generateRSAKeyPair to create 
        public and private keys for both X and Y */
        KeyPair keyPairX = generateRSAKeyPair();
        KeyPair keyPairY = generateRSAKeyPair();

        /* we'll then have to call the saveKeyToFile function to save the keys to 
        XPublic.key etc */
        saveKeyToFile("XPublic.key", keyPairX.getPublic());
        saveKeyToFile("XPrivate.key", keyPairX.getPrivate());
        saveKeyToFile("YPublic.key", keyPairY.getPublic());
        saveKeyToFile("YPrivate.key", keyPairY.getPrivate());


        /*we then need to get a 16 character user input and save the input to a file 
        named symmetric.key
        */

        String AESKey = UserInputAESKey();
        saveAESKeyToFile("symmetric.key", AESKey);

        System.out.println("Keys generated and saved");
        

    }

    private static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException{

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(1024);
        return keyGen.generateKeyPair();

    }

    private static void saveKeyToFile(String filename, Key key) throws IOException, NoSuchAlgorithmException{

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec publicKeySpec;
        RSAPrivateKeySpec privateKeySpec;

        try (FileOutputStream fileOutputStream = new FileOutputStream(filename);
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(fileOutputStream)){
                if (key instanceof PublicKey){
                    publicKeySpec = keyFactory.getKeySpec(key, RSAPublicKeySpec.class);
                    objectOutputStream.writeObject(publicKeySpec.getModulus());
                    objectOutputStream.writeObject(publicKeySpec.getPublicExponent());

                }
                else {
                    privateKeySpec = keyFactory.getKeySpec(key, RSAPrivateKeySpec.class);
                    objectOutputStream.writeObject(privateKeySpec.getModulus());
                    objectOutputStream.writeObject(privateKeySpec.getPrivateExponent());
                }
            
            }
            catch (Exception e){
                System.err.println("Error, key not saved to file: " + e.getMessage());
            }
            

        }
    
    private static String UserInputAESKey(){
        Scanner scanner = new Scanner(System.in);
        String AESKey;
        do{
            System.out.print("Enter 16 characters for an AES key: ");
            AESKey = scanner.nextLine();
        }
        while (AESKey.length() != 16);
        scanner.close();
        return AESKey;

    }

    private static void saveAESKeyToFile(String filename, String AESKey) throws IOException{
        try (FileOutputStream fileOutputStream = new FileOutputStream(filename);
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(fileOutputStream, "UTF-8"))){
            writer.write(AESKey);
        }
        catch (IOException e){
           System.err.println("Error, AESKey not saved to file: " + e.getMessage());

        }
    }
}
