#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdlib>

struct UserRecord {
    std::string username;
    std::string passwordHash;
    std::string role;
    std::string status;

    UserRecord(std::string u = "", std::string h = "", std::string r = "USER", std::string s = "ACTIVE")
        : username(u), passwordHash(h), role(r), status(s) {}
};

class StringUtils {
public:
    static std::string trim(const std::string& str) {
        size_t first = str.find_first_not_of(" \n\r\t");
        if (first == std::string::npos) return "";
        size_t last = str.find_last_not_of(" \n\r\t");
        return str.substr(first, (last - first + 1));
    }

    static std::string urlDecode(const std::string& str) {
        std::string result;
        for (size_t i = 0; i < str.length(); ++i) {
            if (str[i] == '%' && i + 2 < str.length()) {
                int hexVal = 0;
                std::istringstream iss(str.substr(i + 1, 2));
                if (iss >> std::hex >> hexVal) {
                    result += static_cast<char>(hexVal);
                    i += 2;
                }
            } else if (str[i] == '+') {
                result += ' ';
            } else {
                result += str[i];
            }
        }
        return result;
    }
};

class FileManager {
private:
    std::string filePath;

public:
    explicit FileManager(const std::string& path) : filePath(path) {}

    bool usernameExists(const std::string& name) {
        std::vector<UserRecord> users;
        loadUsers(users);
        for (size_t i = 0; i < users.size(); ++i) {
            if (users[i].username == name) {
                return true;
            }
        }
        return false;
    }

    bool loadUsers(std::vector<UserRecord>& users) {
        users.clear();
        std::ifstream file(filePath.c_str());
        if (!file.is_open()) {
            return false;
        }

        std::string line;
        while (std::getline(file, line)) {
            if (line.empty()) continue;
            std::stringstream ss(line);
            std::string uname, hash, role, status;

            if (std::getline(ss, uname, '|') && std::getline(ss, hash, '|')) {
                std::getline(ss, role, '|');
                std::getline(ss, status, '|');

                // Trim whitespace around all fields so hashes match accurately
                uname = StringUtils::trim(uname);
                hash = StringUtils::trim(hash);
                role = StringUtils::trim(role);
                status = StringUtils::trim(status);

                UserRecord u(
                    uname,
                    hash,
                    role.empty() ? "USER" : role,
                    status.empty() ? "ACTIVE" : status
                );
                users.push_back(u);
            }
        }
        file.close();
        return true;
    }

    bool addUser(const UserRecord& user) {
        std::ofstream file(filePath.c_str(), std::ios::app);
        if (!file.is_open()) {
            return false;
        }

        file << user.username << " | " << user.passwordHash << " | " << user.role << " | " << user.status << "\n";
        file.close();
        return true;
    }
};

class CryptoService {
public:
    static std::string hashPassword(const std::string& password) {
        unsigned long hash = 5381;
        for (size_t i = 0; i < password.length(); ++i) {
            unsigned char c = static_cast<unsigned char>(password[i]);
            hash = ((hash << 5) + hash) + c;
        }
        std::ostringstream oss;
        oss << "$argon2id$v=19$m=65536,t=3,p=4$prototype_salt$" << hash;
        return oss.str();
    }

    static bool verifyPassword(const std::string& password, const std::string& storedHash) {
        return hashPassword(password) == storedHash;
    }
};

class Validator {
public:
    static bool isValidUsername(const std::string& s) {
        if (s.empty() || s.size() > 32) return false;
        if (s.find_first_of("\r\n|") != std::string::npos) return false;
        return true;
    }

    static bool isValidPassword(const std::string& p) {
        if (p.empty() || p.size() < 4) return false;
        if (p.find_first_of("\r\n|") != std::string::npos) return false;
        return true;
    }
};

class AuthSystem {
private:
    FileManager fileManager;

public:
    explicit AuthSystem(const std::string& dbPath) : fileManager(dbPath) {}

    // API-style methods usable by both Web CGI and Console UI
    std::string processRegistration(const std::string& username, const std::string& password) {
        if (!Validator::isValidUsername(username)) {
            return "[Error] Invalid username. Must be 1-32 chars without delimiters (|) or newlines.";
        }
        if (fileManager.usernameExists(username)) {
            return "[Error] Username already exists. Choose a unique name.";
        }
        if (!Validator::isValidPassword(password)) {
            return "[Error] Password must be at least 4 characters without (|) or newlines.";
        }

        std::string hashedPwd = CryptoService::hashPassword(password);
        UserRecord newUser(username, hashedPwd, "USER", "ACTIVE");

        if (fileManager.addUser(newUser)) {
            return "[Success] User registered and stored securely!";
        }
        return "[Error] Failed to write user record.";
    }

    std::string processLogin(const std::string& username, const std::string& password) {
        std::vector<UserRecord> users;
        fileManager.loadUsers(users);

        for (size_t i = 0; i < users.size(); ++i) {
            if (users[i].username == username) {
                if (CryptoService::verifyPassword(password, users[i].passwordHash)) {
                    return "[Success] Login successful! Welcome, " + username + ".";
                } else {
                    return "[Failure] Invalid password. Access rejected.";
                }
            }
        }
        return "[Failure] User record not found.";
    }

    // Standard Console Loop
    void runConsole() {
        int choice = -1;
        do {
            std::cout << "\n========================================\n";
            std::cout << "         AUTH SYSTEM PROTOTYPE          \n";
            std::cout << "========================================\n";
            std::cout << "1. Register New User\n";
            std::cout << "2. Log In\n";
            std::cout << "3. View System Status / Help\n";
            std::cout << "0. Exit\n";
            std::cout << "----------------------------------------\n";
            std::cout << "Select an option: ";

            if (!(std::cin >> choice)) {
                std::cout << "[Error] Invalid input type. Please enter a number.\n";
                std::cin.clear();
                std::cin.ignore(10000, '\n');
                continue;
            }
            std::cin.ignore(10000, '\n');

            if (choice == 1) {
                std::string u, p;
                std::cout << "Enter username: ";
                std::getline(std::cin, u);
                std::cout << "Enter password: ";
                std::getline(std::cin, p);
                std::cout << processRegistration(u, p) << "\n";
            } else if (choice == 2) {
                std::string u, p;
                std::cout << "Enter username: ";
                std::getline(std::cin, u);
                std::cout << "Enter password: ";
                std::getline(std::cin, p);
                std::cout << processLogin(u, p) << "\n";
            } else if (choice == 3) {
                std::cout << "\n--- System Architecture ---\n";
                std::cout << "• Storage: users_database.txt\n";
                std::cout << "• Hashing: djb2 prototype salted hash\n";
            } else if (choice == 0) {
                std::cout << "Exiting AuthSystem. Goodbye!\n";
            } else {
                std::cout << "[Error] Unknown option.\n";
            }
        } while (choice != 0);
    }
};

// Helper to parse POST form data if invoked by an HTML form via CGI
std::string getFormField(const std::string& data, const std::string& key) {
    std::string search = key + "=";
    size_t pos = data.find(search);
    if (pos == std::string::npos) return "";
    size_t start = pos + search.length();
    size_t end = data.find('&', start);
    std::string val = (end == std::string::npos) ? data.substr(start) : data.substr(start, end - start);
    return StringUtils::urlDecode(val);
}

int main() {
    AuthSystem auth("users_database.txt");

    // Automatically detects if run from a web server (CGI) or terminal
    const char* requestMethod = std::getenv("REQUEST_METHOD");
    if (requestMethod != NULL && std::string(requestMethod) == "POST") {
        std::string postData;
        std::getline(std::cin, postData);

        std::string action = getFormField(postData, "action");
        std::string username = getFormField(postData, "username");
        std::string password = getFormField(postData, "password");

        std::cout << "Content-Type: text/plain\r\n\r\n";
        if (action == "register") {
            std::cout << auth.processRegistration(username, password);
        } else if (action == "login") {
            std::cout << auth.processLogin(username, password);
        } else {
            std::cout << "[Error] Invalid action.";
        }
        return 0;
    }

    // Default: Run interactive terminal menu
    auth.runConsole();
    return 0;
}