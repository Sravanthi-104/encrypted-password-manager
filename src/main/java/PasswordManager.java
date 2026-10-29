
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.Console;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

public class PasswordManager {

    private static final Path VAULT = Path.of("vault.dat");
    private static final int ITERATIONS = 600_000;
    private static final int SALT_SIZE = 16;
    private static final int NONCE_SIZE = 12;
    private static final int KEY_SIZE = 256;
    private static final SecureRandom RANDOM = new SecureRandom();

    private static SecretKey deriveKey(char[] password, byte[] salt)
            throws Exception {
        PBEKeySpec spec =
                new PBEKeySpec(password, salt, ITERATIONS, KEY_SIZE);

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance(
                    "PBKDF2WithHmacSHA256");

            byte[] key = factory.generateSecret(spec).getEncoded();
            try {
                return new SecretKeySpec(key, "AES");
            } finally {
                Arrays.fill(key, (byte) 0);
            }
        } finally {
            spec.clearPassword();
        }
    }

    private static byte[] encrypt(byte[] data, SecretKey key,
                                  byte[] nonce) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key,
                new GCMParameterSpec(128, nonce));
        return cipher.doFinal(data);
    }

    private static byte[] decrypt(byte[] data, SecretKey key,
                                  byte[] nonce) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key,
                new GCMParameterSpec(128, nonce));
        return cipher.doFinal(data);
    }

    private static char[] readPassword(Scanner scanner, String prompt) {
        Console console = System.console();

        if (console != null) {
            return console.readPassword("%s", prompt);
        }

        System.out.print(prompt);
        return scanner.nextLine().toCharArray();
    }

    private static byte[] readVault() throws Exception {
        return Files.readAllBytes(VAULT);
    }

    private static void saveVault(byte[] salt, byte[] nonce,
                                  byte[] ciphertext) throws Exception {
        ByteBuffer buffer = ByteBuffer.allocate(
                salt.length + nonce.length + ciphertext.length);

        buffer.put(salt);
        buffer.put(nonce);
        buffer.put(ciphertext);

        Files.write(VAULT, buffer.array());
    }

    private static byte[] newNonce() {
        byte[] nonce = new byte[NONCE_SIZE];
        RANDOM.nextBytes(nonce);
        return nonce;
    }

    private static void initializeVault(Scanner scanner)
            throws Exception {
        System.out.println("Create your master password.");
        char[] password = readPassword(scanner, "Master password: ");

        if (password.length < 12) {
            Arrays.fill(password, '\0');
            System.out.println("Use at least 12 characters.");
            return;
        }

        byte[] salt = new byte[SALT_SIZE];
        RANDOM.nextBytes(salt);

        try {
            SecretKey key = deriveKey(password, salt);
            byte[] nonce = newNonce();

            byte[] encrypted = encrypt(new byte[0], key, nonce);
            saveVault(salt, nonce, encrypted);

            System.out.println("Vault created successfully!");
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static SecretKey unlockVault(Scanner scanner)
            throws Exception {
        byte[] file = readVault();

        if (file.length < SALT_SIZE + NONCE_SIZE + 16) {
            throw new IllegalStateException("Invalid vault file.");
        }

        ByteBuffer buffer = ByteBuffer.wrap(file);
        byte[] salt = new byte[SALT_SIZE];
        byte[] nonce = new byte[NONCE_SIZE];
        byte[] ciphertext = new byte[buffer.remaining()
                - SALT_SIZE - NONCE_SIZE];

        buffer.get(salt);
        buffer.get(nonce);
        buffer.get(ciphertext);

        char[] password = readPassword(scanner, "Master password: ");

        try {
            SecretKey key = deriveKey(password, salt);

            // Verify the password by authenticating the encrypted data.
            decrypt(ciphertext, key, nonce);

            return key;
        } finally {
            Arrays.fill(password, '\0');
        }
    }

    private static String encryptText(String text, SecretKey key)
            throws Exception {
        byte[] nonce = newNonce();
        byte[] plaintext = text.getBytes(StandardCharsets.UTF_8);

        try {
            byte[] ciphertext = encrypt(plaintext, key, nonce);
            byte[] combined = ByteBuffer.allocate(
                            nonce.length + ciphertext.length)
                    .put(nonce).put(ciphertext).array();

            return Base64.getEncoder().encodeToString(combined);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    private static String decryptText(String encoded, SecretKey key)
            throws Exception {
        byte[] combined = Base64.getDecoder().decode(encoded);

        if (combined.length < NONCE_SIZE + 16) {
            throw new IllegalArgumentException("Invalid encrypted entry.");
        }

        ByteBuffer buffer = ByteBuffer.wrap(combined);
        byte[] nonce = new byte[NONCE_SIZE];
        buffer.get(nonce);

        byte[] ciphertext = new byte[buffer.remaining()];
        buffer.get(ciphertext);

        byte[] plaintext = decrypt(ciphertext, key, nonce);
        try {
            return new String(plaintext, StandardCharsets.UTF_8);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
    }

    private static String generatePassword() {
        String chars =
                "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
                        + "23456789!@#$%^&*()-_=+";

        StringBuilder result = new StringBuilder();

        for (int i = 0; i < 20; i++) {
            result.append(chars.charAt(
                    RANDOM.nextInt(chars.length())));
        }

        return result.toString();
    }

    public static void main(String[] args) {
        try (Scanner scanner = new Scanner(System.in)) {
            SecretKey key;

            if (!Files.exists(VAULT)) {
                initializeVault(scanner);

                if (!Files.exists(VAULT)) {
                    return;
                }
            }

            try {
                key = unlockVault(scanner);
                System.out.println("Vault unlocked!");
            } catch (Exception e) {
                System.out.println(
                        "Could not unlock vault. Check your password.");
                return;
            }

            while (true) {
                System.out.println("\n--- PASSWORD MANAGER ---");
                System.out.println("1. Add credential");
                System.out.println("2. View credential");
                System.out.println("3. Generate password");
                System.out.println("4. Exit");
                System.out.print("Choose: ");

                String choice = scanner.nextLine();

                try {
                    switch (choice) {
                        case "1" -> {
                            System.out.print("Website/account: ");
                            String account = scanner.nextLine();

                            System.out.print("Username: ");
                            String username = scanner.nextLine();

                            char[] secret = readPassword(
                                    scanner, "Password to save: ");

                            String entry;
                            try {
                                entry = account + "\n" + username
                                        + "\n" + new String(secret);
                            } finally {
                                Arrays.fill(secret, '\0');
                            }

                            String encryptedEntry =
                                    encryptText(entry, key);

                            // Preserve the existing vault entries.
                            String existing = new String(
                                    decrypt(readVault().length > 0
                                                    ? extractCiphertext(readVault())
                                                    : new byte[0],
                                            key, extractNonce(readVault())),
                                    StandardCharsets.UTF_8);

                            String updated = existing.isEmpty()
                                    ? encryptedEntry
                                    : existing + "\n" + encryptedEntry;

                            // A fresh nonce is required for every save.
                            byte[] salt = extractSalt(readVault());
                            byte[] nonce = newNonce();
                            byte[] ciphertext = encrypt(
                                    updated.getBytes(
                                            StandardCharsets.UTF_8),
                                    key, nonce);

                            saveVault(salt, nonce, ciphertext);
                            System.out.println("Credential saved.");
                        }
                        case "2" -> {
                            System.out.print("Website/account: ");
                            String search = scanner.nextLine();

                            String all = decryptVaultContents(key);

                            boolean found = false;
                            for (String encoded : all.split("\n")) {
                                if (encoded.isBlank()) continue;

                                String entry = decryptText(encoded, key);
                                String[] fields = entry.split("\n", 3);

                                if (fields.length == 3
                                        && fields[0].equalsIgnoreCase(search)) {
                                    System.out.println("Account: " + fields[0]);
                                    System.out.println("Username: " + fields[1]);
                                    System.out.println("Password: " + fields[2]);
                                    found = true;
                                    break;
                                }
                            }

                            if (!found) {
                                System.out.println("Account not found.");
                            }
                        }
                        case "3" ->
                                System.out.println(
                                        "Generated password: "
                                                + generatePassword());
                        case "4" -> {
                            System.out.println("Vault closed.");
                            return;
                        }
                        default -> System.out.println("Invalid choice.");
                    }
                } catch (Exception e) {
                    System.out.println("Operation failed.");
                }
            }
        } catch (Exception e) {
            System.out.println("Vault error: " + e.getMessage());
        }
    }

    // Helpers used to read the vault container.
    private static byte[] extractSalt(byte[] file) {
        return Arrays.copyOfRange(file, 0, SALT_SIZE);
    }

    private static byte[] extractNonce(byte[] file) {
        return Arrays.copyOfRange(file, SALT_SIZE,
                SALT_SIZE + NONCE_SIZE);
    }

    private static byte[] extractCiphertext(byte[] file) {
        return Arrays.copyOfRange(file,
                SALT_SIZE + NONCE_SIZE, file.length);
    }

    private static String decryptVaultContents(SecretKey key)
            throws Exception {
        byte[] file = readVault();
        return new String(decrypt(extractCiphertext(file), key,
                extractNonce(file)), StandardCharsets.UTF_8);
    }
}
