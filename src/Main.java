import Rijndael.RijndaelEncrypt;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Введите название файла: ");
        String fileName = scanner.nextLine();

        boolean exitFlag = false;

        System.out.print("Для шифрования файла введите 1, для дешифрации введите 2: ");
        while (!exitFlag) {
            String input = scanner.nextLine();
            if (input.trim().equals("1")) {
                System.out.println("Введите 16 байтный ключ (8 символов)");
                input = scanner.nextLine();
                if (input.trim().length() == 8) {
                    try {
                        RijndaelEncrypt.encryptFileModeOFB(fileName, "encrypted_file.txt", input);
                        System.out.println("Файл зашифрован, вектор инициализации записан в файл vector.txt");
                    } catch (FileNotFoundException e) {
                        System.err.println("Файл " + fileName + " не найден");
                        System.exit(1);
                    } catch (IOException e) {
                        System.err.println("Ошибка чтения файла");
                        System.exit(1);
                    }

                } else System.out.println("Размер ключа не 16 байт");
                exitFlag = true;
            } else if (input.trim().equals("2")) {
                System.out.println("Введите 16 байтный ключ (8 символов)");
                input = scanner.nextLine();
                if (input.trim().length() == 8) {
                    String key = input;
                    System.out.println("Введите имя файла с вектором инициализации");
                    input = scanner.nextLine();
                    try {
                        RijndaelEncrypt.decryptFileModeOFB(fileName, "decrypted_file.txt", key, input);
                        System.out.println("Файл дешифрован");
                    } catch (FileNotFoundException e) {
                        System.err.println(e.getMessage());
                        System.exit(1);
                    } catch (IOException e) {
                        System.err.println("Ошибка чтения файла");
                        System.exit(1);
                    }
                } else System.out.println("Размер ключа не 16 байт");
                exitFlag = true;
            } else System.out.println("Повторите ввод");
        }
    }


}
