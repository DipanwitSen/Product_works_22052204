# 🛍️ Local Marketplace AI Chatbot

This is a **full-featured Flask application** for a local marketplace.  
It includes robust **user authentication**, **product management for sellers**, a **rule-based chatbot with dynamic SQL querying**, and a secure **e-commerce workflow using Razorpay**.

---

## 🚀 Getting Started

Follow these instructions to set up and run the application on your local machine.

### Prerequisites

Ensure you have the following installed:

- **Python 3.x**  
- **pip** (Python package installer)

---

### 1️⃣ Install Dependencies

Navigate to the project directory and install the required Python packages:

```bash
pip install flask werkzeug razorpay

### 2️⃣ **Set Up Environment Variables**

The application requires several environment variables for **security**, **email functionality** (for password reset), and **payment gateway integration**.

**On Linux/macOS (Bash):**

```bash
# General Setup
export SECRET_KEY="your_strong_secret_key_here"
export APP_URL="http://127.0.0.1:5000"

# Email Configuration (for password resets)
export EMAIL_USER="your-email@gmail.com"
export EMAIL_PASS="your-app-password"  # Use a Google App Password

# Razorpay Payment Gateway
export RAZORPAY_KEY="rzp_test_..."
export RAZORPAY_SECRET="..."


| Folder/File                | Purpose                 | Notes                                                                                    |
| -------------------------- | ----------------------- | ---------------------------------------------------------------------------------------- |
| `app.py`                   | Main application engine | Contains Flask routes, database setup, authentication, e-commerce logic, and chatbot API |
| `localmart.db`             | SQLite database         | Stores users, products, cart_items, orders, order_items, wishlist                        |
| `static/`                  | Static assets           | Contains `style.css` and `images/products/`                                              |
| `templates/base.html`      | Master layout           | Header, role-based navigation, shared CSS/fonts                                          |
| `templates/home.html`      | Landing page            | Product grid and chatbot UI                                                              |
| `templates/auth/*.html`    | Auth views              | `login.html`, `signup.html`, `forgot.html`, `reset_password.html`                        |
| `templates/product/*.html` | Product views           | `add_product.html`, `product_details.html`                                               |
| `templates/cart.html`      | Cart page               | Displays cart items and checkout option                                                  |
| `templates/checkout.html`  | Checkout page           | Razorpay payment flow                                                                    |
