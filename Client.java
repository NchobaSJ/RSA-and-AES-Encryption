import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;

public class Client {
    public static void main(String[] args) {
        try (Socket socket = new Socket("127.0.0.1", 5000)) {
            System.out.println("Connected to the server");

            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            // Generate RSA key pair for the client
            KeyPair clientKeyPair = CryptoUtils.generateRSAKeyPair();

            // Receive the server's public key
            PublicKey serverPublicKey = (PublicKey) in.readObject();

            // Send the client's public key to the server
            out.writeObject(clientKeyPair.getPublic());

            // Generate AES key and IV
            SecretKey aesKey = CryptoUtils.generateAESKey();
            byte[] iv = CryptoUtils.generateIV();

            // Send IV to the server
            out.writeObject(iv);

            // Sign the AES key using the client's private key
            String aesKeySignature = CryptoUtils.signData(Base64.getEncoder().encodeToString(aesKey.getEncoded()), clientKeyPair.getPrivate());

            // Encrypt the AES key with the server's public key
            byte[] encryptedAESKey = CryptoUtils.encryptAESKey(aesKey, serverPublicKey);

            // Send the encrypted AES key and its signature
            out.writeObject(encryptedAESKey);
            out.writeObject(aesKeySignature);

            BufferedReader userInput = new BufferedReader(new InputStreamReader(System.in));

            // Bidirectional communication loop
            while (true) {
                // Send encrypted message to the server
                System.out.print("Client: ");
                String clientMessage = userInput.readLine();

                String signedMessage = CryptoUtils.signData(clientMessage, clientKeyPair.getPrivate());
                String encryptedMessage = CryptoUtils.encryptAES(clientMessage + "|" + signedMessage, aesKey, iv);

                out.writeObject(encryptedMessage);

                // Receive and decrypt message from the server
                String encryptedResponse = (String) in.readObject();
                String decryptedResponse = CryptoUtils.decryptAES(encryptedResponse, aesKey, iv);

                String[] parts = decryptedResponse.split("\\|");
                String serverMessage = parts[0];
                String responseSignature = parts[1];

                boolean isVerified = CryptoUtils.verifySignature(serverMessage, responseSignature, serverPublicKey);

                if (isVerified) {
                    System.out.println("Decrypted Server Message: " + serverMessage);
                } else {
                    System.out.println("Message verification failed.");
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
