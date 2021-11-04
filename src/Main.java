import Rijndael.RijndaelEncrypt;

public class Main {

    public static void main(String[] args) {
	    int[][] a = {
                {0xd4, 0xe0, 0xb8, 0x1e},
                {0xbf, 0xb4, 0x41, 0x27},
                {0x5d, 0x52, 0x11, 0x98},
                {0x30, 0xae, 0xf1, 0xe5}
        };
        RijndaelEncrypt.mixColumns(a);
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                System.out.print(Integer.toHexString(a[i][j]) + " ");
            }
            System.out.println();
        }

    }
}
