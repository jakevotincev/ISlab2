import Rijndael.RijndaelEncrypt;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class Main {

    public static void main(String[] args) {
//        int[][] state = {
//                {0x32, 0x88, 0x31, 0xe0},
//                {0x43, 0x5a, 0x31, 0x37},
//                {0xf6, 0x30, 0x98, 0x07},
//                {0xa8, 0x8d, 0xa2, 0x34}
//        };
//        int[][] cipherKey = {
//                {0x2b, 0x28, 0xab, 0x09},
//                {0x7e, 0xae, 0xf7, 0xcf},
//                {0x15, 0xd2, 0x15, 0x4f},
//                {0x16, 0xa6, 0x88, 0x3c}
//        };
//
//        RijndaelEncrypt.encrypt(state, cipherKey);
//
//        for (int i = 0; i < 4; i++) {
//            for (int j = 0; j < 4; j++) {
//                System.out.print(Integer.toHexString(state[i][j]) + " ");
//            }
//            System.out.println();
//        }
//        System.out.println();
//        RijndaelEncrypt.decrypt(state, cipherKey);
//
//
//        for (int i = 0; i < 4; i++) {
//            for (int j = 0; j < 4; j++) {
//                System.out.print(Integer.toHexString(state[i][j]) + " ");
//            }
//            System.out.println();
//        }

        try {
            String vector = RijndaelEncrypt.encryptFileModeOFB("text.txt", "output.txt", "приветик");
            System.out.printf("сгенерированный вектор инициализации %s", vector);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }


}
