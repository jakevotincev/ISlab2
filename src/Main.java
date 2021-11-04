import Rijndael.RijndaelEncrypt;

public class Main {

    public static void main(String[] args) {
	    int[][] a = {
                {0x2b, 0x28, 0xab, 0x09},
                {0x7e, 0xae, 0xf7, 0xcf},
                {0x15, 0xd2, 0x15, 0x4f},
                {0x16, 0xa6, 0x88, 0x3c}
        };
//        RijndaelEncrypt.mixColumns(a);
        RijndaelEncrypt.keyExpansion(a);
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 44; j++) {
                System.out.print(Integer.toHexString(RijndaelEncrypt.expandedKey[i][j]) + " ");
            }
            System.out.println();
        }

    }
}
