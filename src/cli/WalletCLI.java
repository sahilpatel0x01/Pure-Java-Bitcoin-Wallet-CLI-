package cli;

import wallet.KeyManager;
import wallet.Wallet;

import java.util.Scanner;

public class WalletCLI {

    private static final Scanner scanner = new Scanner(System.in);
    private static Wallet currentWallet = null;

    public static void main(String[] args) {
        System.out.println("=========================================");
        System.out.println("   Pure Java Bitcoin Wallet (CLI)   ");
        System.out.println("   NO LIBRARIES - PURE IMPLEMENTATION   ");
        System.out.println("=========================================");
        
        while (true) {
            printMenu();
            System.out.print("> ");
            String choice = scanner.nextLine().trim();
            
            try {
                switch (choice) {
                    case "1":
                        createWallet();
                        break;
                    case "2":
                        importWIF();
                        break;
                    case "3":
                        importWatchOnly();
                        break;
                    case "4":
                        showWallet();
                        break;
                    case "5":
                        System.out.println("Exiting...");
                        return;
                    default:
                        System.out.println("Invalid option.");
                }
            } catch (Exception e) {
                System.out.println("Error: " + e.getMessage());
                e.printStackTrace();
            }
        }
    }

    private static void printMenu() {
        System.out.println("\nOptions:");
        System.out.println("1. Create New Wallet");
        System.out.println("2. Import Private Key (WIF)");
        System.out.println("3. Import Watch-Only Address");
        System.out.println("4. Show Current Wallet Details");
        System.out.println("5. Exit");
    }

    private static void createWallet() {
        System.out.print("Network (mainnet/testnet) [mainnet]: ");
        String net = scanner.nextLine().trim().toLowerCase();
        boolean testnet = net.equals("testnet");

        System.out.print("Use Compressed Public Key? (y/n) [y]: ");
        String comp = scanner.nextLine().trim().toLowerCase();
        boolean compressed = !comp.equals("n");

        System.out.println("Generating key pair... (using SecureRandom)");
        byte[] priv = KeyManager.generatePrivateKey();
        currentWallet = new Wallet(priv, compressed, testnet);
        System.out.println("Wallet created successfully!");
        showWallet();
    }

    private static void importWIF() {
        System.out.print("Enter WIF Private Key: ");
        String wif = scanner.nextLine().trim();
        if (wif.isEmpty()) return;

        try {
            KeyManager.ParsedPrivateKey parsed = KeyManager.wifToPrivateKey(wif);
            // Default to mainnet for imported keys usually, but WIF prefix tells us. 
            // My wifToPrivateKey didn't return network, checking prefix again here or strictly deriving.
            // Simplified: The parsed key is raw bytes. We re-derive.
            // If prefix was 0xEF it's testnet, 0x80 mainnet.
            // Ideally wifToPrivateKey should return this info.
            // For now, I'll assume mainnet unless I check the WIF prefix manually here.
            
            // Re-checking prefix for network detection
            byte[] decoded = crypto.Base58.decode(wif);
            boolean testnet = (decoded[0] & 0xFF) == 0xEF;
            
            currentWallet = new Wallet(parsed.key, parsed.compressed, testnet);
            System.out.println("Wallet imported successfully!");
            showWallet();
        } catch (Exception e) {
            System.out.println("Invalid WIF: " + e.getMessage());
        }
    }

    private static void importWatchOnly() {
        System.out.print("Enter Bitcoin Address: ");
        String addr = scanner.nextLine().trim();
        if (addr.isEmpty()) return;
        
        currentWallet = new Wallet(addr);
        System.out.println("Watch-only wallet imported.");
        showWallet();
    }

    private static void showWallet() {
        if (currentWallet == null) {
            System.out.println("No wallet loaded.");
            return;
        }
        System.out.println(currentWallet.toString());
    }
}
