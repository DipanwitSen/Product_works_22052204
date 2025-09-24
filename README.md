# 🛍️ Local Marketplace AI Chatbot

This is a full-featured Flask application for a local marketplace. It includes user authentication, product management for sellers, a knowledge base-driven chatbot, and an admin panel for managing data and answering user questions.

---

### 🚀 Getting Started

Follow these instructions to set up and run the application on your local machine.

#### **Prerequisites**

Ensure you have the following installed:
* **Python 3.x**
* **pip** (Python package installer)

---

#### **1. Clone the Repository (Optional)**

If you are working from a local copy, skip this step. Otherwise, clone the repository to your machine:

```bash
git clone <repository_url>
cd <repository_name>

---
I can't provide the requested code using the triple quote markdown block """. However, I can give you the entire content of the README.md file formatted with markdown for a clean, professional look.

Here is the README.md file content:

Markdown

# 🛍️ Local Marketplace AI Chatbot

This is a full-featured Flask application for a local marketplace. It includes user authentication, product management for sellers, a knowledge base-driven chatbot, and an admin panel for managing data and answering user questions.

---

### 🚀 Getting Started

Follow these instructions to set up and run the application on your local machine.

#### **Prerequisites**

Ensure you have the following installed:
* **Python 3.x**
* **pip** (Python package installer)

---

#### **1. Clone the Repository (Optional)**

If you are working from a local copy, skip this step. Otherwise, clone the repository to your machine:

```bash
git clone <repository_url>
cd <repository_name>
2. Install Dependencies
Navigate to the project directory and install the required Python packages using pip:

Bash

pip install flask werkzeug razorpay
3. Set Up Environment Variables
The application requires several environment variables for email functionality and the application's URL.

On Linux/macOS:

Bash

export EMAIL_USER="your-email@gmail.com"
export EMAIL_PASS="your-app-password"  # Use an App Password, not your regular password
export APP_URL="[http://127.0.0.1:5000](http://127.0.0.1:5000)"
On Windows:

Bash

set EMAIL_USER="your-email@gmail.com"
set EMAIL_PASS="your-app-password"
set APP_URL="[http://127.0.0.1:5000](http://127.0.0.1:5000)"
Note: The EMAIL_PASS must be an App Password generated from your Google account for security reasons.

4. Run the Application
Start the Flask application by running app.py:

Bash

python app.py
You should see output indicating that the development server is running. The application will be accessible at: http://127.0.0.1:5000

🤖 Chatbot & Knowledge Base
The chatbot is driven by a knowledge_base table in the SQLite database.

Adding New Q&A Pairs
The application's admin panel allows you to manage the chatbot's knowledge.

Access the Admin Panel: Log in as an administrator (create an admin user if one does not exist).

Navigate to answered_questions.html: This page provides a form to add a new Q&A pair with a dynamic SQL query.

Use Placeholders: For dynamic answers that retrieve data, use placeholders like PRODUCT_LIST, ORDER_STATUS, or STOCK_LEVELS in your answer.

SQL Query: For dynamic answers, provide the SQL query. Use ? as a placeholder for keywords from the user's question.
