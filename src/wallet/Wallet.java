package wallet;

public class Wallet {
    private byte[] privateKey;
    private byte[] publicKey;
    private String address;
    private boolean isWatchOnly;
    private boolean isCompressed;
    private boolean isTestnet;

    // Constructors
    public Wallet(byte[] privateKey, boolean compressed, boolean testnet) {
        this.privateKey = privateKey;
        this.isCompressed = compressed;
        this.isTestnet = testnet;
        this.isWatchOnly = false;
        derive();
    }
    
    // Watch only constructor
    public Wallet(String address) {
        this.address = address;
        this.isWatchOnly = true;
    }

    private void derive() {
        if (this.isWatchOnly) return;
        this.publicKey = KeyManager.getPublicKey(this.privateKey, this.isCompressed);
        this.address = KeyManager.getAddress(this.publicKey, this.isTestnet);
    }
    
    public String getWIF() {
        if (isWatchOnly) return null;
        return KeyManager.privateKeyToWIF(privateKey, isCompressed, isTestnet);
    }
    
    public String getAddress() {
        return address;
    }
    
    public byte[] getPublicKey() {
        return publicKey;
    }
    
    // Helper to print hex
    public String getPublicKeyHex() {
        if (publicKey == null) return null;
        StringBuilder sb = new StringBuilder();
        for (byte b : publicKey) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
    
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        sb.append("=== Bitcoin Wallet ===\n");
        sb.append("Address: ").append(address).append("\n");
        if (!isWatchOnly) {
            sb.append("WIF:     ").append(getWIF()).append("\n");
            sb.append("Pub Key: ").append(getPublicKeyHex()).append("\n");
        } else {
            sb.append("(Watch-Only)\n");
        }
        return sb.toString();
    }
}
