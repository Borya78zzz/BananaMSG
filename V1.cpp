#include <iostream>
#include <string>
#include <vector>
#include <thread>
#include <cstdint>
#include <fstream>
#include <sstream>
#include <sodium.h>
#include <boost/asio.hpp>

#ifdef _WIN32
#include <windows.h>
#endif

using tcp = boost::asio::ip::tcp;

struct Contact {
    std::string name;
    std::string ip;
};

// Класс, отвечающий за шифрование сессии
class SecureSession {
private:
    unsigned char publicKey[crypto_box_PUBLICKEYBYTES];
    unsigned char secretKey[crypto_box_SECRETKEYBYTES];
    unsigned char peerPublicKey[crypto_box_PUBLICKEYBYTES];

public:
    SecureSession() {
        if (sodium_init() < 0) {
            throw std::runtime_error("Ошибка инициализации libsodium!");
        }
        crypto_box_keypair(publicKey, secretKey);
    }

    const unsigned char* getMyPublicKey() const { return publicKey; }

    void setPeerPublicKey(const unsigned char* peerKey) {
        std::copy(peerKey, peerKey + crypto_box_PUBLICKEYBYTES, peerPublicKey);
    }

    std::vector<unsigned char> encryptMessage(const std::string& message) {
        std::vector<unsigned char> ciphertext(crypto_box_MACBYTES + message.length());
        unsigned char nonce[crypto_box_NONCEBYTES];
        randombytes_buf(nonce, sizeof(nonce));

        if (crypto_box_easy(ciphertext.data(), 
                            reinterpret_cast<const unsigned char*>(message.c_str()), 
                            message.length(), nonce, peerPublicKey, secretKey) != 0) {
            throw std::runtime_error("Сбой шифрования!");
        }
        
        std::vector<unsigned char> payload;
        payload.insert(payload.end(), nonce, nonce + crypto_box_NONCEBYTES);
        payload.insert(payload.end(), ciphertext.begin(), ciphertext.end());
        return payload;
    }

    std::string decryptMessage(const std::vector<unsigned char>& payload) {
        if (payload.size() < crypto_box_NONCEBYTES + crypto_box_MACBYTES) {
            throw std::runtime_error("Пакет слишком мал");
        }

        const unsigned char* nonce = payload.data();
        const unsigned char* ciphertext = payload.data() + crypto_box_NONCEBYTES;
        size_t ciphertext_len = payload.size() - crypto_box_NONCEBYTES;

        std::vector<unsigned char> decrypted(ciphertext_len - crypto_box_MACBYTES);

        if (crypto_box_open_easy(decrypted.data(), ciphertext, ciphertext_len, 
                                 nonce, peerPublicKey, secretKey) != 0) {
            throw std::runtime_error("Сообщение подделано или ключи не совпадают!");
        }

        return std::string(decrypted.begin(), decrypted.end());
    }
};

// Чтение контактов из файла
std::vector<Contact> load_contacts() {
    std::vector<Contact> contacts;
    std::ifstream file("contacts.txt");
    
    if (!file.is_open()) {
        std::ofstream create_file("contacts.txt");
        create_file << "Alice 127.0.0.1\n";
        create_file << "Bob 192.168.1.50\n";
        create_file.close();
        contacts.push_back({"Alice", "127.0.0.1"});
        contacts.push_back({"Bob", "192.168.1.50"});
        return contacts;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        std::stringstream ss(line);
        std::string name, ip;
        if (ss >> name >> ip) {
            contacts.push_back({name, ip});
        }
    }
    return contacts;
}

// Правильное чтение русского языка
std::string get_user_input() {
#ifdef _WIN32
    HANDLE hConsole = GetStdHandle(STD_INPUT_HANDLE);
    wchar_t wbuf[2048];
    DWORD read = 0;
    ReadConsoleW(hConsole, wbuf, 2048, &read, NULL);
    if (read > 0 && wbuf[read - 1] == L'\n') read--;
    if (read > 0 && wbuf[read - 1] == L'\r') read--;
    wbuf[read] = L'\0';
    if (read == 0) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, NULL, 0, NULL, NULL);
    std::string result(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wbuf, -1, &result[0], size, NULL, NULL);
    return result;
#else
    std::string text;
    std::getline(std::cin, text);
    return text;
#endif
}

void receive_loop(tcp::socket* socket, SecureSession* session) {
    try {
        while (true) {
            uint32_t len = 0;
            boost::asio::read(*socket, boost::asio::buffer(&len, sizeof(len)));
            
            std::vector<unsigned char> payload(len);
            boost::asio::read(*socket, boost::asio::buffer(payload));
            
            std::string msg = session->decryptMessage(payload);
            std::cout << "\n[Собеседник]: " << msg << "\nВы: " << std::flush;
        }
    } catch (...) {
        std::cout << "\n[Сеть] Соединение разорвано собеседником.\n";
        exit(0);
    }
}

int main() {
#ifdef _WIN32
    SetConsoleOutputCP(CP_UTF8);
#endif

    try {
        SecureSession session;
        boost::asio::io_context io_context;
        tcp::socket socket(io_context);
        std::vector<Contact> contacts = load_contacts();

        std::string target_ip = "";

        while (target_ip.empty()) {
            std::cout << "=== МЕССЕНДЖЕР E2EE ===\n";
            std::cout << "1 - Ждать подключения (Режим сервера)\n";
            std::cout << "2 - Подключиться к контакту из списка\n";
            std::cout << "3 - Подключиться по прямому IP\n";
            std::cout << "4 - Перезагрузить список контактов (при смене IP)\n";
            std::cout << "5 - Выйти из программы\n> ";
            
            int choice;
            if (!(std::cin >> choice)) {
                std::cin.clear();
                std::cin.ignore(256, '\n');
                continue;
            }

            if (choice == 1) {
                tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 8080));
                std::cout << "Ожидание подключения на порту 8080...\n";
                acceptor.accept(socket);
                std::cout << "Клиент подключился!\n";
                break;
            } 
            else if (choice == 2) {
                if (contacts.empty()) {
                    std::cout << "Список контактов пуст!\n\n";
                    continue;
                }
                std::cout << "\nВыбери контакт:\n";
                for (size_t i = 0; i < contacts.size(); ++i) {
                    std::cout << i + 1 << " - " << contacts[i].name << " (" << contacts[i].ip << ")\n";
                }
                std::cout << "0 - Назад\n> ";
                
                int c_choice;
                std::cin >> c_choice;
                if (c_choice > 0 && c_choice <= static_cast<int>(contacts.size())) {
                    target_ip = contacts[c_choice - 1].ip;
                }
            } 
            else if (choice == 3) {
                std::cout << "Введи IP адрес сервера: ";
                std::cin >> target_ip;
            } 
            else if (choice == 4) {
                contacts = load_contacts();
                std::cout << "[Успех] Список контактов обновлен из файла contacts.txt!\n\n";
            }
            else if (choice == 5) {
                std::cout << "Завершение работы... До встречи!\n";
                return 0;
            }
        }

        if (!target_ip.empty()) {
            std::cout << "Подключение к " << target_ip << ":8080...\n";
            socket.connect(tcp::endpoint(boost::asio::ip::make_address(target_ip), 8080));
            std::cout << "Успешное подключение к серверу!\n";
        }

        std::cout << "Обмен криптографическими ключами...\n";
        boost::asio::write(socket, boost::asio::buffer(session.getMyPublicKey(), crypto_box_PUBLICKEYBYTES));
        
        unsigned char peerKey[crypto_box_PUBLICKEYBYTES];
        boost::asio::read(socket, boost::asio::buffer(peerKey, crypto_box_PUBLICKEYBYTES));
        session.setPeerPublicKey(peerKey);
        std::cout << "*** Защищенный E2EE канал установлен! ***\n";
        std::cout << "(Для выхода напиши: exit или выйти)\n\n";

        std::cin.ignore(256, '\n');

        std::thread t(receive_loop, &socket, &session);
        t.detach();

        // Главный цикл чата
        while (true) {
            std::cout << "Вы: " << std::flush;
            std::string text = get_user_input();
            if (text.empty()) continue;

            // --- БЛОК ВЫХОДА ---
            if (text == "exit" || text == "Exit" || text == "выйти" || text == "Выйти") {
                std::cout << "\nОтключение от чата...\n";
                socket.close(); // Разрываем соединение
                break;          // Выходим из цикла и программы
            }
            // -------------------

            std::vector<unsigned char> encrypted = session.encryptMessage(text);
            uint32_t len = encrypted.size();
            
            boost::asio::write(socket, boost::asio::buffer(&len, sizeof(len)));
            boost::asio::write(socket, boost::asio::buffer(encrypted));
        }

    } catch (const std::exception& e) {
        std::cerr << "Критическая ошибка: " << e.what() << "\n";
    }

    return 0;
}