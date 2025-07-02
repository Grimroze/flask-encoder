# 🔐 Flask Message Encoder / Decoder

A stylish, responsive web application that allows users to securely **encode and decode messages** using a custom key — built with **Flask** for the backend and a beautiful modern **HTML/CSS UI inspired by Uiverse.io**.

---

## 🌐 Live Demo

👉 [https://flask-encoder.onrender.com/](#)
## 🚀 Features

- 🔒 **Secure custom encoding/decoding** using a symmetric key algorithm
- ✨ Beautiful **glassmorphic UI** with floating labels and animated buttons
- ⚙️ Built using **Python Flask**
- 🧠 Backend logic hidden from user
- 🌈 Fully responsive & interactive front-end

---

## 🛠️ Tech Stack

- **Frontend**: HTML5, CSS3 (Uiverse.io UI components)
- **Backend**: Python, Flask
- **Deployment**: [Render](https://render.com)

---

## 📂 Folder Structure
flask-encoder-deploy/
│
├── app.py
├── requirements.txt
└── templates/
└── index.html
## 🧪 How It Works

1. User enters a message and a secret key.
2. Chooses between **encode** or **decode** mode.
3. Backend processes using a character-shifting + Base64 encoding algorithm.
4. Result is displayed back securely on the same page.

---

## 🔧 Local Development

Clone the repo and run it locally:

```bash
git clone https://github.com/Grimroze/flask-encoder.git
cd flask-encoder
pip install -r requirements.txt
python app.py
