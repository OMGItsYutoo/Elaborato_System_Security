package it.unina.crypto;

import java.io.Console;
import java.util.Arrays;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        char[] keystorePassword = resolvePassword(args, scanner);

        boolean running = true;
        try {
            while (running) {
                System.out.println("\n==================================================");
                System.out.println("   SYSTEM SECURITY - CRYPTOGRAPHY & PKI LAB");
                System.out.println("==================================================");
                System.out.println("1. Basic Crypto (AES-CBC & RSA-2048 Raw Sign/Verify)");
                System.out.println("2. Build 3-Tier PKI (Root -> Intermediate -> Signer)");
                System.out.println("3. EU DSS Lab (Cert Inspection, CAdES & PAdES)");
                System.out.println("4. CVE-2026-8763 Lab (Name Constraints Validation)");
                System.out.println("5. Run Full Pipeline (1 -> 2 -> 3 -> 4)");
                System.out.println("0. Exit");
                System.out.print("\nSelect an option: ");

                String choice = scanner.nextLine().trim();

                try {
                    switch (choice) {
                        case "1" -> EserciziCrittografia.run();
                        case "2" -> PkiBuilder.build3TierPki(PkiBuilder.DEFAULT_P12_PATH, keystorePassword);
                        case "3" -> DssSignatureLab.run(keystorePassword);
                        case "4" -> Cve8763Lab.run();
                        case "5" -> {
                            EserciziCrittografia.run();
                            PkiBuilder.build3TierPki(PkiBuilder.DEFAULT_P12_PATH, keystorePassword);
                            DssSignatureLab.run(keystorePassword);
                            Cve8763Lab.run();
                        }
                        case "0" -> {
                            running = false;
                            System.out.println("Exiting...");
                        }
                        default -> System.out.println("[!] Invalid option. Try again.");
                    }
                } catch (Exception e) {
                    System.err.println("[ERROR] Module execution failed: " + e.getMessage());
                    e.printStackTrace();
                }
            }
        } finally {
            // Wipe password from memory on exit
            Arrays.fill(keystorePassword, '\0');
            scanner.close();
        }
    }

    private static char[] resolvePassword(String[] args, Scanner scanner) {
        if (args.length > 0 && !args[0].isBlank()) {
            System.out.println("[AUTH] Keystore password loaded from CLI argument.");
            return args[0].toCharArray();
        }

        Console console = System.console();
        if (console != null) {
            char[] pwd = console.readPassword("[AUTH] Enter PKCS#12 keystore password: ");
            if (pwd != null && pwd.length > 0) {
                return pwd;
            }
        }

        // Fallback for IDE terminals (e.g., VS Code Debug Console) where System.console() is null
        System.out.print("[AUTH] Enter PKCS#12 keystore password: ");
        return scanner.nextLine().trim().toCharArray();
    }
}