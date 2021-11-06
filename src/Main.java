import Rijndael.RijndaelEncrypt;

import java.io.IOException;

public class Main {

    public static void main(String[] args) {
        try {
            RijndaelEncrypt.encryptFileModeOFB("text.txt", "output.txt", "приветик");
            RijndaelEncrypt.decryptFileModeOFB("output.txt", "newtext.txt", "приветик", "vector.txt");
//            System.out.printf("сгенерированный вектор инициализации %s", vector);

        } catch (IOException e) {
            e.printStackTrace();
        }

    }


}
