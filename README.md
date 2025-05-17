# CyberCipher
CyberCipher Web is a web-based encryption and decryption tool that provides a user-friendly interface for various cryptographic methods. This project aims to offer a platform for exploring and utilizing different encryption techniques for both text and files.
![image](https://github.com/user-attachments/assets/3c10ebb3-2ed5-453b-812f-76eaeb3d2acc)
![image](https://github.com/user-attachments/assets/49e215e5-42dd-418b-9ea8-62c4b0bfdc5a)
![image](https://github.com/user-attachments/assets/d0adbb41-44d1-4cdd-bbe8-43f8c18b3d84)
![Screenshot (1537)](https://github.com/user-attachments/assets/4807484c-5fb6-4c9f-9afd-750664547984)
![image](https://github.com/user-attachments/assets/9db5ff30-455e-4850-877c-028448facca7)


**Key Features**

* **Text Encryption/Decryption:**
     * Supports multiple encryption algorithms:
     * Caesar Cipher: A simple substitution cipher.
     * Mirror Shift Cipher: A custom cipher that reverses the input and shifts characters.
     * Dynamic Shift Cipher: A custom cipher with dynamic character shifts and block reversal.
     * Vigenère Cipher: A polyalphabetic substitution cipher with optional autokey and block permutation.
     * AES-256-CBC: Advanced Encryption Standard with a 256-bit key in Cipher Block Chaining mode, with optional random IV and HMAC.
 * Key-based encryption for applicable ciphers.
 * Optional salt for the Dynamic Shift Cipher.
 * Options for Vigenère cipher: autokey and block permutation.
 * Options for AES: custom key (hexadecimal), random Initialization Vector (IV), and Hash-based Message Authentication Code (HMAC).

* **File Encryption/Decryption:**
    * Supports encryption and decryption of files.

* **User Interface:**
    * Clean and responsive design using HTML, CSS (Tailwind CSS), and JavaScript.
    * Intuitive selection of encryption types.
    * Modal-based welcome message.

## Technologies Used

* **Frontend:**
    * HTML5: For structuring the web page.
    * CSS3: For styling.
    * Tailwind CSS: A utility-first CSS framework for rapid design.
    * JavaScript: For client-side logic and interactivity.
    * Google Fonts (Inter, Poppins): For enhanced typography.

* **Backend:**
    * Node.js: JavaScript runtime environment.
    * Express.js: Web framework for handling server-side logic and routing.
