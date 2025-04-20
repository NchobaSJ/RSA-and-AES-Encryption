import javax.crypto.SecretKey;
import java.io.*;
import java.net.*;
import java.security.*;
import java.util.Base64;

public class Server {
    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(5000)) {
            System.out.println("Server is listening on port 5000");

            // Wait for client connection
            Socket socket = serverSocket.accept();
            System.out.println("Client connected");

            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());

            // Generate RSA key pair for the server
            KeyPair serverKeyPair = CryptoUtils.generateRSAKeyPair();

            // Send the server's public key to the client
            out.writeObject(serverKeyPair.getPublic());

            // Receive the client's public key
            PublicKey clientPublicKey = (PublicKey) in.readObject();

            // Receive IV from the client
            byte[] iv = (byte[]) in.readObject();

            // Receive the encrypted AES key and its signature
            byte[] encryptedAESKey = (byte[]) in.readObject();
            String aesKeySignature = (String) in.readObject();

            // Decrypt the AES key using the server's private key
            SecretKey aesKey = CryptoUtils.decryptAESKey(encryptedAESKey, serverKeyPair.getPrivate());
            System.out.println("Successfully decrypted AES key from client.");

            // Verify the AES key's signature
            boolean isKeyVerified = CryptoUtils.verifySignature(
                    Base64.getEncoder().encodeToString(aesKey.getEncoded()),
                    aesKeySignature,
                    clientPublicKey
            );

            if (isKeyVerified) {
                System.out.println("AES key signature verified successfully.");
            } else {
                System.out.println("AES key signature verification failed.");
                socket.close();
                return;
            }

            BufferedReader serverInput = new BufferedReader(new InputStreamReader(System.in));

            // Bidirectional communication loop
            while (true) {
                // Receive and decrypt message from the client
                String encryptedMessage = (String) in.readObject();
                String decryptedMessage = CryptoUtils.decryptAES(encryptedMessage, aesKey, iv);

                String[] parts = decryptedMessage.split("\\|");
                String clientMessage = parts[0];
                String messageSignature = parts[1];

                boolean isVerified = CryptoUtils.verifySignature(clientMessage, messageSignature, clientPublicKey);

                if (isVerified) {
                    System.out.println("Decrypted Client Message: " + clientMessage);
                } else {
                    System.out.println("Message verification failed.");
                }

                // Send an encrypted response back to the client
                System.out.print("Server: ");
                String serverMessage = serverInput.readLine();

                String signedResponse = CryptoUtils.signData(serverMessage, serverKeyPair.getPrivate());
                String encryptedResponse = CryptoUtils.encryptAES(serverMessage + "|" + signedResponse, aesKey, iv);

                out.writeObject(encryptedResponse);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
