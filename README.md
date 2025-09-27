🛍️ Local Marketplace AI Chatbot
This is a full-featured Flask application for a local marketplace. It includes robust user authentication, product management for sellers, a rule-based chatbot with dynamic SQL querying, and a secure e-commerce workflow using Razorpay.

🚀 Getting Started
Follow these instructions to set up and run the application on your local machine.

Prerequisites
Ensure you have the following installed:

Python 3.x

pip (Python package installer)

1. Install Dependencies
Navigate to the project directory and install the required Python packages:

pip install flask werkzeug razorpay
# NOTE: The provided code does not use Groq for the chatbot, 
# relying instead on hardcoded logic and database lookups for speed.

2. Set Up Environment Variables
The application requires several environment variables for security, email functionality (for password reset), and payment gateway integration.

On Linux/macOS (Bash):

# General Setup
export SECRET_KEY="your_strong_secret_key_here"
export APP_URL="[http://127.0.0.1:5000](http://127.0.0.1:5000)"

# Email Configuration (for password resets)
export EMAIL_USER="your-email@gmail.com"
export EMAIL_PASS="your-app-password"  # Use a Google App Password

# Razorpay Payment Gateway
export RAZORPAY_KEY="rzp_test_..."
export RAZORPAY_SECRET="..."

3. Run the Application
Start the Flask application by running app.py:

python app.py

The application will be accessible at: http://127.0.0.1:5000

📂 Project Structure & Core Files
File/Directory

Purpose

Key Routes

app.py

The main application engine. Contains all Flask routes, database initialization, authentication, e-commerce logic (cart, orders, Razorpay), and the Chatbot API (/chatbot).

/, /login, /cart, /checkout, /chatbot

localmart.db

The SQLite Database. Stores all application data: users, products, cart_items, orders, order_items, and wishlist.

N/A

static/

Contains static files. Primarily style.css for application aesthetics and the images/products/ folder for uploaded product photos.

N/A

templates/base.html

The Master Layout for all pages. Defines the header, role-based navigation, and includes shared CSS/fonts.

N/A

templates/home.html

The Landing Page. Displays the product grid and hosts the client-side JavaScript for the Chatbot UI.

/

templates/auth/*.html

User Authentication views: login.html, signup.html, forgot.html, reset_password.html.

/login, /signup

templates/product/*.html

Seller product management (add_product.html) and buyer detail view (product_details.html).

/add_product, /product/<int:product_id>

templates/cart.html / checkout.html

User e-commerce workflow, including the Razorpay integration script on the checkout page.

/cart, /checkout

⚙️ System Flows & Application Logic
1. User Authentication and Roles
Hashing: User passwords are securely stored using generate_password_hash from werkzeug.security.

Roles: Users are assigned one of three roles: user, seller, or admin.

The base.html template uses Jinja2 logic ({% if session.get('role') == 'seller' %}) to conditionally display navigation links (e.g., "Add Product").

Route access in app.py is guarded by checks (if session.get('role') != 'seller': flash...).

Password Reset: Uses the EMAIL_USER and EMAIL_PASS environment variables to send a secure, temporary, token-based reset link via SMTP.

2. E-commerce & Payments (Razorpay)
Cart Management: The /add_to_cart and /remove_from_cart routes manipulate data in the cart_items table based on the logged-in user's ID.

Checkout (/create_order):

The client-side JavaScript on checkout.html first calls the Flask route /create_order.

This route calculates the total amount from the user's cart items and uses the Razorpay SDK (razorpay_client.order.create) to securely generate a unique Razorpay Order ID.

The Order ID and the RAZORPAY_KEY are sent back to the client.

Payment Processing:

The client script initiates the Razorpay Checkout Modal using the returned Order ID.

Upon successful payment, Razorpay sends a payment ID and signature back to the client.

The client then calls the Flask route /payment_success, passing these credentials.

Verification and Finalization:

The Flask route uses razorpay_client.utility.verify_payment_signature to verify the payment integrity using the RAZORPAY_SECRET.

If verified, the status of the new order is set to Paid in the orders and order_items tables.

3. 🤖 Chatbot Logic (/chatbot)
The chatbot is implemented using a structured, priority-based parsing engine in app.py. It is designed for maximum efficiency in an e-commerce context.

A. Command Triage (Highest Priority)
The system checks for specific keywords and regex patterns for immediate, database-driven actions:

Command Type

Example Query

Database Action

Order Status

where is my order #12345?

SELECT order status from orders table.

Specifications

specs of the new laptop

SELECT specifications from the products table.

Seller Pending Orders

do I have any pending orders?

JOIN orders and products to find pending orders for the seller's products.

Seller Stock Update

update stock of X to 50

UPDATE products table.

B. Product Search (High Priority)
If no explicit command is found, the chatbot assumes a product query:

Extraction: Uses re (regex) to extract the product name and any price constraints (e.g., "find shoes under ₹5000").

Query Construction: Dynamically builds a flexible SQL SELECT query (WHERE name LIKE ? OR description LIKE ?) with conditional AND price < X clauses based on detected terms (e.g., under, above, between).

Dynamic Display: Products found via the query are returned as a JSON payload, which the client-side JavaScript in home.html renders visually as product cards directly in the chat window, providing an interactive shopping experience.

C. General Chat (Low Priority - Now Removed for Focus)
Original Design: The initial design included a fallback to the Groq LLM if the database search failed.

Current State: To ensure a stable and consistent, command-focused experience without external API dependencies, the Groq LLM integration has been removed. The chatbot now only handles the explicit E-commerce and Seller-focused commands detailed above.
