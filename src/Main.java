public class Main {
    public static void main(String[] args) throws Exception {
        EncryptionUtils encryptionUtils = new EncryptionUtils();
         String password = "Привет меня зовут Денис";
         String secret_key = "ertg";


        var encrypted = encryptionUtils.encrypt(password,secret_key);

        System.out.println("Зашифрованное сообщение "+encrypted);

        var decrypted = encryptionUtils.decrypt(encrypted,secret_key);
        System.out.println("Сообщение после дЕШИФРОВАНИЯ "+decrypted);
//[B@48533e64

    }
}