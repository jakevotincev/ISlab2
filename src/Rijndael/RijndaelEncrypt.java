package Rijndael;

import java.io.*;
import java.util.*;

public class RijndaelEncrypt {
    private static final int[] SBOX = {
            0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
            0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
            0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
            0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
            0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
            0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
            0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
            0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
            0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
            0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
            0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
            0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
            0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
            0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
            0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
            0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16
    };

    private static final int[] INV_SBOX = {
            0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
            0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
            0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
            0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
            0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
            0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
            0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
            0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
            0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
            0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
            0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
            0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
            0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
            0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
            0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
            0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
    };

    private static final int[][] CX = {
            {2, 3, 1, 1},
            {1, 2, 3, 1},
            {1, 1, 2, 3},
            {3, 1, 1, 2},
    };

    private static final int[][] INV_CX = {
            {0xe, 0xb, 0xd, 0x9},
            {0x9, 0xe, 0xb, 0xd},
            {0xd, 0x9, 0xe, 0xb},
            {0xb, 0xd, 0x9, 0xe}
    };

    private static final int[][] RCON = {
            {0x01, 0x00, 0x00, 0x00},
            {0x02, 0x00, 0x00, 0x00},
            {0x04, 0x00, 0x00, 0x00},
            {0x08, 0x00, 0x00, 0x00},
            {0x10, 0x00, 0x00, 0x00},
            {0x20, 0x00, 0x00, 0x00},
            {0x40, 0x00, 0x00, 0x00},
            {0x80, 0x00, 0x00, 0x00},
            {0x1b, 0x00, 0x00, 0x00},
            {0x36, 0x00, 0x00, 0x00}
    };

    private static final int[][] expandedKey = new int[4][44];

    public static void encryptFileModeOFB(String inputFile, String outputFile, String key) throws IOException {
        int[][] vector = generateIV();
        writeFile("vector.txt", Collections.singletonList(vector), false);
        List<int[][]> encryptedText = encryptOFB(inputFile, key, vector);
        writeFile(outputFile, encryptedText, false);
    }

    public static void decryptFileModeOFB(String inputFile, String outputFile, String key, String vectorFile) throws IOException {
        int[][] vector;
        List<int[][]> vectorList;
        try {
            vectorList = readFile(vectorFile);
        } catch (FileNotFoundException e) {
            throw new FileNotFoundException("Файл " + vectorFile + " не найден");
        }
        Optional<int[][]> optionalVector = vectorList.stream().findFirst();
        if (optionalVector.isPresent())
            vector = optionalVector.get();
        else throw new IllegalArgumentException("empty vector");
        List<int[][]> decryptedText = encryptOFB(inputFile, key, vector);
        writeFile(outputFile, decryptedText, true);
    }

    private static List<int[][]> encryptOFB(String inputFile, String key, int[][] vector) throws IOException {
        int[][] cypherKey = convertToSquare(key);
        List<int[][]> text = readFile(inputFile);
        List<int[][]> decryptedText = new ArrayList<>();
        for (int[][] state : text) {
            int[][] result;
            encrypt(vector, cypherKey);
            result = xorMatrixes(vector, state);
            decryptedText.add(result);
        }
        return decryptedText;
    }

    public static void encrypt(int[][] state, int[][] cipherKey) {
        keyExpansion(cipherKey);
        addRoundKey(state, 0);
        for (int i = 1; i < 10; i++) {
            subBytes(state);
            shiftRows(state);
            mixColumns(state, false);
            addRoundKey(state, i);
        }
        subBytes(state);
        shiftRows(state);
        addRoundKey(state, 10);
    }

    public static void decrypt(int[][] state, int[][] cipherKey) {
        keyExpansion(cipherKey);
        addRoundKey(state, 10);
        for (int i = 9; i > 0; i--) {
            invShiftRows(state);
            invSubBytes(state);
            addRoundKey(state, i);
            mixColumns(state, true);
        }
        invShiftRows(state);
        invSubBytes(state);
        addRoundKey(state, 0);
    }

    private static void invSubBytes(int[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] = INV_SBOX[state[i][j]];
            }
        }
    }

    private static void subBytes(int[][] state) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] = SBOX[state[i][j]];
            }
        }
    }

    private static void subBytes(int[] input) {
        for (int i = 0; i < 4; i++) {
            input[i] = SBOX[input[i]];
        }
    }

    private static void invShiftRows(int[][] state) {
        for (int i = 1; i < 4; i++) {
            rightRotate(state[i], i, 4);
        }
    }

    private static void rightRotate(int[] arr, int d, int n) {
        int[] temp = new int[n - d];
        if (n - d >= 0) System.arraycopy(arr, 0, temp, 0, n - d);
        for (int i = n - d; i < n; i++) {
            arr[i - n + d] = arr[i];
        }
        if (n - d >= 0) System.arraycopy(temp, 0, arr, d, n - d);
    }

    private static void shiftRows(int[][] state) {
        int[] newRow = new int[4];
        for (int i = 1; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                newRow[j] = state[i][(j + i) % 4];
            }
            state[i] = Arrays.copyOf(newRow, newRow.length);
        }
    }

    private static void mixColumns(int[][] state, boolean inv) {
        for (int i = 0; i < 4; i++) {
            int[] column = new int[4];
            for (int j = 0; j < 4; j++) {
                int r = 0;
                for (int k = 0; k < 4; k++) {
                    if (inv)
                        r ^= mult(state[k][i], INV_CX[j][k]);
                    else
                        r ^= mult(state[k][i], CX[j][k]);
                }
                column[j] = r;
            }
            for (int j = 0; j < 4; j++) {
                state[j][i] = column[j];
            }
        }
    }

    private static void addRoundKey(int[][] state, int keyNum) {
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                state[i][j] ^= expandedKey[i][keyNum * 4 + j];
            }
        }
    }

    private static void keyExpansion(int[][] cipherKey) {
        for (int i = 0; i < 4; i++) {
            System.arraycopy(cipherKey[i], 0, expandedKey[i], 0, 4);
        }
        for (int i = 4; i < 44; i += 4) {
            int[] curWord = rotWord(expandedKey, i - 1);
            subBytes(curWord);
            curWord = xorWords(expandedKey, i - 4, curWord, i / 4 - 1);
            for (int j = 0; j < 4; j++) {
                expandedKey[j][i] = curWord[j];
            }
            for (int j = 1; j < 4; j++) {
                curWord = xorWords(expandedKey, i + j - 4, i + j - 1);
                for (int k = 0; k < 4; k++) {
                    expandedKey[k][i + j] = curWord[k];
                }
            }
        }
    }

    private static int[] xorWords(int[][] expandedKey, int columnNum, int[] word, int rconNum) {
        int[] result = new int[4];
        for (int i = 0; i < 4; i++) {
            result[i] = expandedKey[i][columnNum] ^ word[i] ^ RCON[rconNum][i];
        }
        return result;
    }

    private static int[] xorWords(int[][] expandedKey, int columnNum1, int columnNum2) {
        int[] result = new int[4];
        for (int i = 0; i < 4; i++) {
            result[i] = expandedKey[i][columnNum1] ^ expandedKey[i][columnNum2];
        }
        return result;
    }

    private static int[][] xorMatrixes(int[][] a, int[][] b) {
        int[][] result = new int[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                result[i][j] = a[i][j] ^ b[i][j];
            }
        }
        return result;
    }

    private static int[] rotWord(int[][] input, int columnNum) {
        int[] rotatedColumn = new int[4];
        for (int i = 0; i < 4; i++) {
            rotatedColumn[i] = input[(i + 1) % 4][columnNum];
        }
        return rotatedColumn;
    }

    private static int mult(int a, int c) {
        int result;
        switch (c) {
            case (0x2):
                result = mul2(a);
                break;
            case (0x3):
                result = mul2(a) ^ a;
                break;
            case (0x9):
                result = mul2(mul2(mul2(a))) ^ a;
                break;
            case (0xb):
                result = mul2(mul2(mul2(a))) ^ mul2(a) ^ a;
                break;
            case (0xd):
                result = mul2(mul2(mul2(a))) ^ mul2(mul2(a)) ^ a;
                break;
            case (0xe):
                result = mul2(mul2(mul2(a))) ^ mul2(mul2(a)) ^ mul2(a);
                break;
            default:
                result = a * c;
        }
        if (result > 255) {
            result &= 0b11111111;
        }
        return result;
    }

    private static int mul2(int a) {
        if (a < 0x80) a *= 2;
        else {
            a = a * 2 ^ 0x1b;
            a %= 0x100;
        }
        return a;
    }

    private static int[][] generateIV() {
        int[][] vector = new int[4][4];
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                vector[i][j] = (int) (Math.random() * 255);
            }
        }
        return vector;
    }

    //метод для преобразования строки в матрицу, строка не больше 8 байт
    private static int[][] convertToSquare(String text) {
        if (text.length() > 8) throw new IllegalArgumentException(text);
        int[][] matrix = new int[4][4];
        byte[] byteStr = text.getBytes();
        int index = 0;
        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                if (index < byteStr.length)
                    matrix[i][j] = unsignedToBytes(byteStr[index]);
                else matrix[i][j] = 0;
                index++;
            }
        }
        return matrix;
    }

    private static List<int[][]> readFile(String filename) throws IOException {
        List<int[][]> text = new ArrayList<>();
        try (FileInputStream fin = new FileInputStream(filename)) {
            int i;
            List<Integer> buffer = new ArrayList<>();
            while ((i = fin.read()) != -1) {
                buffer.add(i);
            }

            Iterator<Integer> iterator = buffer.iterator();
            while (iterator.hasNext()) {
                int[][] state = new int[4][4];
                for (int j = 0; j < 4; j++) {
                    for (int k = 0; k < 4; k++) {
                        if (iterator.hasNext())
                            state[j][k] = iterator.next();

                    }
                }
                text.add(state);
            }
        }
        return text;
    }


    private static void writeFile(String fileName, List<int[][]> text, boolean countZeros) throws IOException {
        try (FileOutputStream fos = new FileOutputStream(fileName)) {
            byte[] buffer = new byte[text.size() * 16];
            int index = 0;
            int zeroCount = 0;
            for (int[][] matrix : text) {
                for (int i = 0; i < 4; i++) {
                    for (int j = 0; j < 4; j++) {
                        if (matrix[i][j] == 0)
                            zeroCount++;
                        buffer[index] = (byte) matrix[i][j];
                        index++;
                    }
                }
            }
            if (!countZeros) zeroCount = 0;
            fos.write(buffer, 0, buffer.length - zeroCount);
        }
    }

    private static int unsignedToBytes(byte b) {
        return b & 0xFF;
    }
}
