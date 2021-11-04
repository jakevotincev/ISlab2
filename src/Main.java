import Rijndael.RijndaelEncrypt;

public class Main {

    public static void main(String[] args) {
	    int[][] a = {
                {25, 160, 154, 233},
                {61, 244, 198, 248},
                {227, 226, 141, 72},
                {190, 43, 42, 8}
        };
        RijndaelEncrypt.shiftRows(a);
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                System.out.print(a[i][j] + " ");
            }
            System.out.println();
        }
    }
}
