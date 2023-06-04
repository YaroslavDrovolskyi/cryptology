package ua.drovolskyi.cryptology.test;

import java.security.NoSuchAlgorithmException;

public class Main {
    public static void main(String[] args) throws NoSuchAlgorithmException {
        System.out.println("========== Check DSA algorithm ==========");
        checkDsaAlgorithm();

        System.out.println("\n\n========== Check AES algorithm ==========");
        checkAesAlgorithm();
    }

    public static void checkDsaAlgorithm() throws NoSuchAlgorithmException {
        byte[] message = new byte[]{0x05, 0x05, 0x05, 0x05, 0x05};

        // sign message
        DsaAlgorithm signatory = new DsaAlgorithm();
        signatory.generateDomainParametersAndKeys();
        byte[][] signature = signatory.sign(message);

        // retrieve public parameters and public key
        byte[] p = signatory.getP();
        byte[] q = signatory.getQ();
        byte[] g = signatory.getG();
        byte[] y = signatory.getY();

        // create signature checker, passing to it public parameters and public key
        DsaAlgorithm checker = new DsaAlgorithm();
        checker.setDomainParameters(p, q, g);
        checker.setPublicKey(y);


        // check real message with sender's real signature
        boolean result1 = checker.checkSignature(message, signature);
        System.out.println("Check real message with sender's real signature: " + result1);

        // check fake message with sender's real signature
        byte[] fakeMessage = new byte[]{0x01, 0x02, 0x03, 0x04, 0x05};
        boolean result2 = checker.checkSignature(fakeMessage, signature);
        System.out.println("Check fake message with sender's real signature: " + result2);

        // check real message with fake signature
        byte[][] fakeSignature = new byte[][]{
                {0x01, 0x02, 0x03, 0x04, 0x05},
                {0x01, 0x02, 0x03, 0x04, 0x05}};
        boolean result3 = checker.checkSignature(message, fakeSignature);
        System.out.println("Check real message with fake signature:          " + result3);
    }


    public static void checkAesAlgorithm() throws NoSuchAlgorithmException {
        AesAlgorithm aes = new AesAlgorithm();

        byte[] text = new byte[]{0x55, 0x63, 0x33, Integer.valueOf(0xff).byteValue(),
                0x55, 0x63, 0x33, Integer.valueOf(0xff).byteValue(),
                0x55, 0x63, 0x33, Integer.valueOf(0xff).byteValue(),
                0x55, 0x63, 0x33, Integer.valueOf(0xff).byteValue()};
//        byte[] text = new byte[]{0x05, 0x02, 0x03, 0x04, 0x01, 0x02, 0x05, 0x04, 0x01, 0x02, 0x03, 0x04,
//                0x01, 0x02, 0x05, 0x05};

        String password = "password";

        byte[] cipher = aes.encrypt(text, password);
        byte[] outputText = aes.decrypt(cipher, password);

        System.out.print("Input  text: "); printArray(text);
        System.out.print("Cipher:      "); printArray(cipher);
        System.out.print("Output text: "); printArray(outputText);
    }

    public static void printArray(byte[] array){
        for(int i = 0; i < array.length; i++){
            String s = Integer.toHexString(Byte.toUnsignedInt(array[i]));
            if(s.length() == 1){
                s = " " + s;
            }
            System.out.print(s + " ");
        }
        System.out.println();
    }
}
