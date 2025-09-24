# This is a full-featured Flask application for a local marketplace.
# It includes user authentication (signup, login, logout), product management for sellers,
# a knowledge base-driven chatbot, and an admin panel.

import os, sqlite3, random
from flask import Flask, render_template, request, redirect, url_for, session, flash, jsonify, get_flashed_messages
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import razorpay
from functools import wraps
import re
import smtplib
from email.mime.text import MIMEText

# You MUST set these environment variables
EMAIL_USER = os.getenv("EMAIL_USER")
EMAIL_PASS = os.getenv("EMAIL_PASS")
EMAIL_SERVER = os.getenv("EMAIL_SERVER", "smtp.gmail.com")
EMAIL_PORT = int(os.getenv("EMAIL_PORT", 587))
APP_URL = os.getenv("APP_URL", "http://127.0.0.1:5000") # Your app's URL

def send_email(to_email, subject, body):
    if not EMAIL_USER or not EMAIL_PASS:
        print("Email not configured. Skipping email sending.")
        return

    try:
        msg = MIMEText(body)
        msg["Subject"] = subject
        msg["From"] = EMAIL_USER
        msg["To"] = to_email

        with smtplib.SMTP(EMAIL_SERVER, EMAIL_PORT) as server:
            server.starttls()
            server.login(EMAIL_USER, EMAIL_PASS)
            server.sendmail(EMAIL_USER, to_email, msg.as_string())
        print(f"Email sent successfully to {to_email}")
    except Exception as e:
        print(f"Failed to send email: {e}")
# Initialize the Flask application
app = Flask(__name__)
# Set a secret key for session management, using an environment variable for security
app.secret_key = os.environ.get("SECRET_KEY", "supersecret")

# Define PINs for admin and dbmanager roles
# IMPORTANT: In a production environment, these should be stored securely, e.g., as environment variables.
ADMIN_PIN = "admin_super_secret_pin"
DBMANAGER_PIN = "dbmanager_super_secret_pin"


# This custom Jinja2 filter is added to fix a potential error when splitting strings in templates.
@app.template_filter('split')
def split_filter(s, separator=None):
    if s:
        return s.split(separator)
    return []

# Configure the upload folder for product images and ensure it exists
UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Razorpay client (Test keys) for handling payments
# In a production environment, these should be securely stored and not hard-coded.
razorpay_client = razorpay.Client(auth=("rzp_test_RJbeRtchCzjRnl", "U1n6sacDbHO3CDCUstNBCs4C"))

# Database configuration
DB_NAME = 'database.db'

# ------------------ DATABASE FUNCTIONS ------------------
def get_db_connection():
    """Establishes and returns a connection to the SQLite database."""
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    """Initializes the database schema and populates with initial data."""
    conn = get_db_connection()
    cursor = conn.cursor()
    # Create tables if they don't exist
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE,
            password TEXT NOT NULL,
            role TEXT DEFAULT 'user'
        )''')
    cursor.execute(
        """
        CREATE TABLE IF NOT EXISTS password_reset_tokens (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL,
            token TEXT NOT NULL UNIQUE,
            expiry_date TIMESTAMP NOT NULL
        );
    """
    )
    # Update the products table to include all required columns
    # Update the products table to include all required columns
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY,
        seller_id INTEGER,
        name TEXT NOT NULL,
        price REAL NOT NULL,
        image_url TEXT,
        color TEXT,
        size TEXT,
        variant TEXT,
        stock INTEGER,
        specifications TEXT,
        FOREIGN KEY (seller_id) REFERENCES users(id)
    )''')
    # Updated orders table to include 'quantity' and 'variant' columns
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER,
        buyer_id INTEGER,
        seller_id INTEGER,
        amount REAL,
        quantity INTEGER,
        variant TEXT,
        status TEXT,
        razorpay_payment_id TEXT,
        razorpay_order_id TEXT,
        razorpay_signature TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (product_id) REFERENCES products(id),
        FOREIGN KEY (buyer_id) REFERENCES users(id),
        FOREIGN KEY (seller_id) REFERENCES users(id)
    )''')
    # Updated table to include a new `sql_query` column
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS knowledge_base (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        question TEXT UNIQUE NOT NULL,
        answer TEXT,
        sql_query TEXT
    )''')
    
    # Populate the knowledge base with initial questions and answers
    cursor.execute("SELECT COUNT(*) FROM knowledge_base")
    if cursor.fetchone()[0] == 0:
        initial_knowledge = [
            ("what is your return policy", "Our return policy allows returns within 30 days of purchase for a full refund or exchange.", None),
            ("how do i contact customer support", "You can contact customer support by emailing support@localmart.com or calling our helpline at +123456789.", None),
            ("what are your shipping options", "We offer standard and express shipping options. Standard shipping takes 5-7 business days, while express takes 2-3 business days.", None),
            ("is cash on delivery available", "Yes, Cash on Delivery (COD) is available for eligible orders.", None),
            ("how do i add a new product", "You can add a new product by going to the 'Add Product' page.", None),
            ("what are your payment methods", "We accept credit/debit cards, net banking, and UPI.", None),
            ("how do i reset my password", "Please go to the login page and click on 'Forgot Password'.", None),
            ("how can i track my order", "You can track your order status on the 'My Orders' page.", None),
            ("how do i apply a coupon", "You can apply a coupon code during the checkout process.", None),
            ("i need a refund", "For a refund, please contact our customer support team with your order details.", None),
            ("how do i report a seller", "You can report a seller by contacting our support team with the seller's name and details of the issue.", None),
            ("how can i change profile", "You can change your profile details by going to the 'Profile' page.", None),
            ("change profile", "You can change your profile details by going to the 'Profile' page.", None)
        ]
        cursor.executemany("INSERT INTO knowledge_base (question, answer, sql_query) VALUES (?,?,?)", initial_knowledge)

    # Create default users if they don't exist
    default_users = [
        ("admin", "admin@example.com", "admin123", "admin"),
        ("dbmanager", "dbmanager@example.com", "dbpass123", "dbmanager"),
        ("seller", "seller@example.com", "seller123", "seller")
    ]
    for username, email, password, role in default_users:
        cursor.execute("SELECT * FROM users WHERE username=?", (username,))
        if not cursor.fetchone():
            cursor.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                            (username, email, generate_password_hash(password), role))
    
    conn.commit()
    conn.close()

# Run the database initialization on application startup
init_db()

# ------------------ AUTHENTICATION DECORATORS ------------------
def login_required(f):
    """Decorator to ensure a user is logged in before accessing a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash("Please log in to access this page.", "warning")
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(roles):
    """
    Decorator to restrict access to a route based on a user's role(s).
    `roles` can be a single string or a list of strings.
    """
    if not isinstance(roles, list):
        roles = [roles]
        
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if 'role' not in session or session['role'] not in roles:
                flash("You don't have permission to access that page.", "danger")
                return redirect(url_for('home'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# ------------------ AUTHENTICATION ROUTES ------------------

@app.route("/signup", methods=["GET", "POST"])
def signup():
    """Handles user signup."""
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])
        role = request.form["role"]
        pin = request.form.get("pin")

        # Check for PIN if role is admin or dbmanager
        if role == 'admin' and pin != ADMIN_PIN:
            flash("Incorrect PIN for Admin signup.", "danger")
            return redirect(url_for("signup"))
        if role == 'dbmanager' and pin != DBMANAGER_PIN:
            flash("Incorrect PIN for DB Manager signup.", "danger")
            return redirect(url_for("signup"))

        conn = get_db_connection()
        try:
            conn.execute("INSERT INTO users (username, email, password, role) VALUES (?, ?, ?, ?)",
                         (username, email, password, role))
            conn.commit()
            flash("Signup successful! Please log in.", "success")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username or email already exists!", "danger")
        finally:
            conn.close()
            
    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Handles user login and redirects based on role."""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
        conn.close()
        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash("Logged in successfully!", "success")
            
            # Redirect based on user role
            if user["role"] == 'admin':
                return redirect(url_for("admin"))
            elif user["role"] == 'dbmanager':
                return redirect(url_for("db_manager"))
            elif user["role"] == 'seller':
                return redirect(url_for("seller_orders"))
            else:
                return redirect(url_for("home"))
        else:
            flash("Invalid username or password!", "danger")
    return render_template("login.html")

@app.route("/logout")
def logout():
    """Logs the user out and clears the session."""
    session.clear()
    flash("Logged out successfully!", "success")
    return redirect(url_for("login"))

import uuid
import datetime

@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    """Handles the forgot password request."""
    if request.method == "POST":
        email = request.form.get("email")
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash("Invalid email address.", "danger")
            return redirect(url_for("forgot"))

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()

        if user:
            # Generate a unique, time-limited token
            token = str(uuid.uuid4())
            expiry = datetime.datetime.now() + datetime.timedelta(hours=1)
            
            # Store the token in the database
            conn.execute(
                "INSERT INTO password_reset_tokens (email, token, expiry_date) VALUES (?, ?, ?)",
                (email, token, expiry),
            )
            conn.commit()
            conn.close()

            # Create the reset link and send the email
            reset_link = f"{APP_URL}/reset?token={token}"
            body = f"Hello,\n\nTo reset your password, click on the following link: {reset_link}\n\nThis link will expire in one hour.\n\nIf you did not request a password reset, please ignore this email.\n\nThank you,\nYour App Team"
            send_email(email, "Password Reset Request", body)
            flash("A password reset link has been sent to your email.", "success")
        else:
            flash("Email not found. Please check the address.", "danger")
        return redirect(url_for("forgot"))

    return render_template("forgot.html")

@app.route("/reset", methods=["GET", "POST"])
def reset():
    """Handles the password reset form using a token."""
    token = request.args.get("token")
    if not token:
        flash("Invalid or missing token.", "danger")
        return redirect(url_for("login"))

    conn = get_db_connection()
    token_data = conn.execute(
        "SELECT * FROM password_reset_tokens WHERE token = ? AND expiry_date > ?",
        (token, datetime.datetime.now()),
    ).fetchone()

    if not token_data:
        flash("Token is invalid or has expired.", "danger")
        conn.close()
        return redirect(url_for("forgot"))

    if request.method == "POST":
        new_password = request.form.get("password")
        confirm_password = request.form.get("confirm_password")

        if new_password != confirm_password:
            flash("Passwords do not match.", "danger")
            conn.close()
            return redirect(url_for("reset", token=token))

        # Update the user's password and delete the token
        hashed_password = generate_password_hash(new_password)
        conn.execute(
            "UPDATE users SET password = ? WHERE email = ?",
            (hashed_password, token_data["email"]),
        )
        conn.execute(
            "DELETE FROM password_reset_tokens WHERE token = ?", (token,)
        )
        conn.commit()
        conn.close()

        flash("Your password has been reset successfully. Please log in.", "success")
        return redirect(url_for("login"))

    conn.close()
    return render_template("reset.html", token=token)
# ------------------ CORE APPLICATION ROUTES ------------------
@app.route("/")
@app.route("/home")
def home():
    """Displays the home page with a list of all products."""
    conn = get_db_connection()
    products = conn.execute("SELECT * FROM products").fetchall()
    conn.close()
    return render_template("home.html", products=products)

# ------------------ CHATBOT ROUTE ------------------
@app.route("/chat", methods=["POST"])
def chat():
    """Handles user messages and provides chatbot responses."""
    user_message = request.json.get("message").lower().strip()
    conn = get_db_connection()
    response_text = "I'm sorry, I don't have an answer for that. An administrator will review your question shortly."
    products = None
    role = session.get('role', 'guest')
    
    try:
        # Check for simple greetings
        greetings = ["hi", "hello", "hey", "hola", "namaste"]
        if any(greeting in user_message for greeting in greetings):
            return jsonify({"message": "Hello! How can I help you today? You can ask me about our products, or if you're a seller, you can ask about your store's performance."})
        
        # New logic to find a dynamic answer first
        dynamic_answer_from_kb = conn.execute("SELECT answer, sql_query FROM knowledge_base WHERE ? LIKE '%' || question || '%' AND sql_query IS NOT NULL", (user_message,)).fetchone()
        if dynamic_answer_from_kb:
            answer_template = dynamic_answer_from_kb['answer']
            sql_query = dynamic_answer_from_kb['sql_query']
            
            # Extract keyword from user message if the query has a placeholder
            match = re.search(r'(.+?)\s+(?:under|in|less than)\s+₹?(\d+)', user_message)
            keyword = ''
            if match:
                keyword = re.sub(r'^(?:give me|get me|find|show me|search for|about|product|brand|a)\s*', '', match.group(1)).strip()

            if keyword and '%s' in sql_query:
                data_result = conn.execute(sql_query, (f'%{keyword}%',)).fetchall()
            else:
                data_result = conn.execute(sql_query).fetchall()

            if data_result:
                # Format the data into a string to insert into the answer template
                formatted_data = ""
                if 'PRODUCT_LIST' in answer_template:
                    formatted_data = ", ".join([f"{row['name']} at ₹{row['price']}" for row in data_result])
                elif 'ORDER_STATUS' in answer_template:
                    formatted_data = ", ".join([f"Order #{row['id']}: {row['status']}" for row in data_result])
                elif 'STOCK_LEVELS' in answer_template:
                    formatted_data = ", ".join([f"{row['name']}: {row['stock']}" for row in data_result])

                response_text = answer_template.replace("PRODUCT_LIST", formatted_data).replace("ORDER_STATUS", formatted_data).replace("STOCK_LEVELS", formatted_data)
                
                # Check if it's a product list query and include product details
                if 'products' in sql_query:
                    products = [{"id": p["id"], "name": p["name"], "price": p["price"], "image": p["image"]} for p in data_result]

            else:
                response_text = "I couldn't find any information for that."
            
            return jsonify({"message": response_text, "products": products})

        # First, try to find a direct answer in the knowledge base
        answer_from_kb = conn.execute("SELECT answer FROM knowledge_base WHERE ? LIKE '%' || question || '%' AND sql_query IS NULL", (user_message,)).fetchone()
        if answer_from_kb and answer_from_kb['answer']:
            return jsonify({"message": answer_from_kb['answer']})

        # --- Dynamic Product and Order Queries ---
        
        # New logic to handle "show me all products"
        if "show me all products" in user_message or "view all products" in user_message:
            products_db = conn.execute("SELECT id, name, price, image FROM products").fetchall()
            if products_db:
                response_text = "Here are all the products we have:"
                products = [{"id": p["id"], "name": p["name"], "price": p["price"], "image": p["image"]} for p in products_db]
            else:
                response_text = "There are no products available at the moment."

        # New logic for "products in range"
        elif re.search(r'₹?(\d+)\s+to\s+₹?(\d+)', user_message):
            match_range = re.search(r'₹?(\d+)\s+to\s+₹?(\d+)', user_message)
            min_price = float(match_range.group(1))
            max_price = float(match_range.group(2))
            products_db = conn.execute("SELECT id, name, price, image FROM products WHERE price BETWEEN ? AND ?", (min_price, max_price)).fetchall()
            if products_db:
                response_text = f"Here are some products in the range of ₹{min_price} to ₹{max_price}:"
                products = [{"id": p["id"], "name": p["name"], "price": p["price"], "image": p["image"]} for p in products_db]
            else:
                response_text = f"I couldn't find any products in the range of ₹{min_price} to ₹{max_price}."
        
        # New logic for exact price search (e.g., "for ₹1000", "equal to ₹500")
        elif re.search(r'(?:for|equal to|exactly)\s+₹?(\d+)', user_message):
            match_exact = re.search(r'(?:for|equal to|exactly)\s+₹?(\d+)', user_message)
            exact_price = float(match_exact.group(1))
            products_db = conn.execute("SELECT id, name, price, image FROM products WHERE price = ?", (exact_price,)).fetchall()
            if products_db:
                response_text = f"Here are some products priced at exactly ₹{exact_price}:"
                products = [{"id": p["id"], "name": p["name"], "price": p["price"], "image": p["image"]} for p in products_db]
            else:
                response_text = f"I couldn't find any products priced at exactly ₹{exact_price}."
        
       # Original flexible product search (e.g., "give me apple", "find me a phone")
        elif re.search(r'(?:give me|get me|find|show me|search for|about|product|brand)\s*(.+)', user_message):
            search_query_raw = re.search(r'(?:give me|get me|find|show me|search for|about|product|brand)\s*(.+)', user_message).group(1).strip().replace("?","")
            search_query = f"%{search_query_raw}%"
            # Corrected line: 'image' is changed to 'image_url'
            products_db = conn.execute("SELECT id, name, price, image_url FROM products WHERE name LIKE ? OR specifications LIKE ? OR variant LIKE ?",(search_query, search_query, search_query)).fetchall()
            if products_db:
                response_text = f"Here's what I found for '{search_query_raw}':"
                products = [{"id": p["id"], "name": p["name"], "price": p["price"], "image": p["image_url"]} for p in products_db]
            else:
                response_text = f"I couldn't find any products matching '{search_query_raw}'."

        elif re.search(r'(.+?)\s+(?:under|in|less than|of)\s+₹?(\d+)', user_message):
            match_product_price = re.search(r'(.+?)\s+(?:under|in|less than|of)\s+₹?(\d+)', user_message)
            product_name_raw = match_product_price.group(1).strip()
            price_limit = float(match_product_price.group(2))
    
            # Refine the product name to remove prefixes like "give me" or "show me"
            product_name_refined = re.sub(r'^(?:give me|get me|find|show me|search for|about|product|brand|a)\s*', '', product_name_raw).strip()
            search_query = f"%{product_name_refined}%"
            products_db = conn.execute("SELECT id, name, price, image_url FROM products WHERE (name LIKE ? OR specifications LIKE ? OR variant LIKE ?) AND price <= ?",
                                 (search_query, search_query, search_query, price_limit)).fetchall()
    
            if products_db:
                response_text = f"Here's what I found for '{product_name_refined.capitalize()}' under ₹{price_limit}:"
                products = [{"id": p["id"], "name": p["name"], "price": p["price"], "image": p["image_url"]} for p in products_db]
            else:
                response_text = f"I couldn't find any products matching '{product_name_refined.capitalize()}' under ₹{price_limit}."
        # Original flexible product search (e.g., "give me apple", "find me a phone")
        elif re.search(r'(?:give me|get me|find|show me|search for|about|product|brand)\s*(.+)', user_message):
            search_query_raw = re.search(r'(?:give me|get me|find|show me|search for|about|product|brand)\s*(.+)', user_message).group(1).strip().replace("?","")
            search_query = f"%{search_query_raw}%"
            products_db = conn.execute("SELECT id, name, price, image FROM products WHERE name LIKE ? OR specifications LIKE ? OR variant LIKE ?",(search_query, search_query, search_query)).fetchall()
            if products_db:
                response_text = f"Here's what I found for '{search_query_raw}':"
                products = [{"id": p["id"], "name": p["name"], "price": p["price"], "image": p["image"]} for p in products_db]
            else:
                response_text = f"I couldn't find any products matching '{search_query_raw}'."
        
        # Product specifications
        elif "specifications" in user_message and "of" in user_message:
            product_name = user_message.split("of")[-1].strip().replace("?", "")
            product_spec = conn.execute("SELECT specifications FROM products WHERE name LIKE ?",(f"%{product_name}%",)).fetchone()
            if product_spec and product_spec['specifications']:
                response_text = f"The specifications for {product_name.capitalize()} are: {product_spec['specifications']}"
            else:
                response_text = f"I couldn't find specifications for {product_name.capitalize()}."

        # Order tracking (Buyer)
        elif "order" in user_message and 'user_id' in session:
            order_match = re.search(r'order\s+#?(\d+)', user_message)
            if order_match:
                order_id = int(order_match.group(1))
                order = conn.execute("SELECT status FROM orders WHERE id = ? AND buyer_id = ?", (order_id, session['user_id'])).fetchone()
                if order:
                    response_text = f"Order #{order_id} has a status of: {order['status'].capitalize()}"
                else:
                    response_text = "I couldn't find that order. Please make sure the order ID is correct."
            else:
                response_text = "Please provide your order number to check its status. For example, 'Where is my order #12345?'"
        
        # --- Seller-specific Queries ---
        elif role == 'seller':
            if "update price of" in user_message and "to ₹" in user_message:
                parts = re.split(r'update price of|to ₹', user_message)
                product_name = parts[1].strip()
                new_price = float(parts[2].strip())
                conn.execute("UPDATE products SET price = ? WHERE name LIKE ? AND seller_id = ?", (new_price, f"%{product_name}%", session['user_id']))
                conn.commit()
                response_text = f"The price of {product_name.capitalize()} has been updated to ₹{new_price}."
            
            elif "delete product" in user_message:
                product_name = user_message.split("delete product")[-1].strip().replace("from my store", "").strip()
                conn.execute("DELETE FROM products WHERE name LIKE ? AND seller_id = ?", (f"%{product_name}%", session['user_id']))
                conn.commit()
                response_text = f"The product {product_name.capitalize()} has been deleted."
            
            elif "check stock" in user_message or "stock levels" in user_message:
                stock_levels = conn.execute("SELECT name, stock FROM products WHERE seller_id = ?", (session['user_id'],)).fetchall()
                if stock_levels:
                    stock_list = [f"{p['name']}: {p['stock']}" for p in stock_levels]
                    response_text = "Here are your current stock levels:\n" + "\n".join(stock_list)
                else:
                    response_text = "You do not have any products listed yet."
            
            elif "pending orders" in user_message:
                pending_orders = conn.execute("SELECT o.id, p.name FROM orders o JOIN products p ON o.product_id = p.id WHERE p.seller_id = ? AND o.status = 'pending'", (session['user_id'],)).fetchall()
                if pending_orders:
                    order_list = [f"Order #{o['id']} ({o['name']})" for o in pending_orders]
                    response_text = "Here are your pending orders:\n" + "\n".join(order_list)
                else:
                    response_text = "You do not have any pending orders."

        # --- Admin-specific Queries ---
        elif role == 'admin':
            if "unanswered questions" in user_message:
                unanswered_q = conn.execute("SELECT id, question FROM knowledge_base WHERE answer IS NULL").fetchall()
                if unanswered_q:
                    q_list = [q['question'] for q in unanswered_q]
                    response_text = "Here are the unanswered questions:\n" + "\n".join(q_list)
                else:
                    response_text = "There are no unanswered questions at this time."

            elif "show me all registered users" in user_message:
                users_list = conn.execute("SELECT username, email, role FROM users").fetchall()
                if users_list:
                    user_details = [f"Username: {u['username']}, Email: {u['email']}, Role: {u['role']}" for u in users_list]
                    response_text = "Here are the registered users:\n" + "\n".join(user_details)
                else:
                    response_text = "No users found."

            elif "add a new table" in user_message or "run custom sql" in user_message or "delete table" in user_message:
                response_text = "I'm sorry, for security reasons, I cannot perform direct database schema modifications or run custom SQL queries via chat. Please contact the system administrator."

        # Fallback: If no specific query is matched, log the question and provide a generic response
        if products is None:
            # Check if the question already exists as an unanswered question to avoid duplicates
            existing_question = conn.execute("SELECT id FROM knowledge_base WHERE question = ? AND answer IS NULL", (user_message,)).fetchone()
            if not existing_question:
                conn.execute("INSERT INTO knowledge_base (question) VALUES (?)", (user_message,))
                conn.commit()
            
            # This is the final fallback message
            response_text = "I'm sorry, I don't have an answer for that. An administrator will review your question shortly."

    except Exception as e:
        print(f"Chatbot error: {e}")
        response_text = "An error occurred while processing your request. My apologies."
    finally:
        conn.close()
    
    response = {"message": response_text}
    if products:
        response["products"] = products
        
    return jsonify(response)


# ------------------ SELLER ROUTES ------------------
@app.route("/add_product", methods=["GET", "POST"])
@login_required
@role_required(['seller', 'admin'])
def add_product():
    """Allows a seller to add a new product."""
    if request.method == "POST":
        name = request.form["name"]
        price = float(request.form["price"])
        variant = request.form.get("variant", "")
        stock = int(request.form.get("stock", 0))
        specifications = request.form.get("specifications", "")

        image_file = request.files["image"]
        filename = secure_filename(image_file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image_file.save(filepath)

        conn = get_db_connection()
        # Correct the INSERT query to match the table schema
        conn.execute("INSERT INTO products (seller_id, name, price, image_url, variant, stock, specifications) VALUES (?, ?, ?, ?, ?, ?, ?)",
             (session["user_id"], name, price, filename, variant, stock, specifications))
        conn.commit()
        conn.close()
        flash("Product added successfully!", "success")
        return redirect(url_for("home"))
    return render_template("add_product.html")


# ------------------ BUYER ROUTES ------------------
@app.route("/buy/<int:product_id>", methods=["GET"])
@login_required
def buy(product_id):
    """Initiates a purchase by creating a Razorpay order."""
    conn = get_db_connection()
    product = conn.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    if not product:
        return "Product not found", 404

    # Get quantity and variant from the URL parameters
    quantity = int(request.args.get('quantity', 1))
    selected_variants = {}
    for key, value in request.args.items():
        if key.startswith('variant-'):
            variant_name = key.replace('variant-', '')
            selected_variants[variant_name] = value
    
    # Format variants into a string to pass to the template
    variant_string = "|".join([f"{k}={v}" for k, v in selected_variants.items()])

    amount = int(product["price"] * quantity * 100) # Razorpay requires amount in paise

    order_receipt = f"receipt_{random.randint(10000, 99999)}"
    data = {
        "amount": amount, 
        "currency": "INR",
        "receipt": order_receipt
    }

    razorpay_order = razorpay_client.order.create(data=data)
    conn.close()
    return render_template("checkout.html", product=product, razorpay_order=razorpay_order, quantity=quantity, variant_string=variant_string)

@app.route("/payment_success", methods=["POST"])
@login_required
def payment_success():
    """Handles the callback after a successful Razorpay payment."""
    payment_id = request.form.get("razorpay_payment_id")
    order_id = request.form.get("razorpay_order_id")
    signature = request.form.get("razorpay_signature")
    product_id = request.args.get("product_id")
    quantity = int(request.args.get("quantity", 1))
    variant_string = request.args.get("variants", "")

    conn = get_db_connection()
    product = conn.execute("SELECT * FROM products WHERE id = ?", (product_id,)).fetchone()
    if not product:
        conn.close()
        return "Product not found", 404

    total_amount = product['price'] * quantity
    seller_id = product['seller_id']

    params_dict = {
        'razorpay_order_id': order_id,
        'razorpay_payment_id': payment_id,
        'razorpay_signature': signature
    }

    try:
        razorpay_client.utility.verify_payment_signature(params_dict)
        payment_status = "success"
        message = "Payment Successful!"
        flash(message, "success")
    except razorpay.errors.SignatureVerificationError:
        payment_status = "failed"
        message = "Payment Failed! Signature verification failed."
        flash(message, "danger")

    conn.execute("INSERT INTO orders (product_id, buyer_id, seller_id, amount, quantity, variant, status, razorpay_payment_id, razorpay_order_id, razorpay_signature) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                 (product_id, session["user_id"], seller_id, total_amount, quantity, variant_string, payment_status, payment_id, order_id, signature))
    conn.commit()
    conn.close()

    return redirect(url_for("my_orders"))

# ------------------ BUYER ORDER ROUTES ------------------

@app.route('/my_orders')
@login_required
def my_orders():
    """Displays all orders for the logged-in user."""
    conn = get_db_connection()
    try:
        # Join the orders and products tables to get all necessary data
        orders = conn.execute("""
            SELECT o.*, p.name AS product_name, p.image_url AS product_image, p.price AS unit_price
            FROM orders o
            JOIN products p ON o.product_id = p.id
            WHERE o.buyer_id = ?
            ORDER BY o.created_at DESC
        """, (session['user_id'],)).fetchall()
        
        # Check if the user is a seller to display their orders as well
        if session['role'] == 'seller':
            seller_orders = conn.execute("""
                SELECT o.*, p.name AS product_name, p.image_url AS product_image, u.username AS buyer_name
                FROM orders o
                JOIN products p ON o.product_id = p.id
                JOIN users u ON o.buyer_id = u.id
                WHERE o.seller_id = ?
                ORDER BY o.created_at DESC
            """, (session['user_id'],)).fetchall()
        else:
            seller_orders = None

    except sqlite3.Error as e:
        flash(f"Database error: {e}", "danger")
        orders = []
        seller_orders = None
    finally:
        conn.close()

    return render_template("my_orders.html", orders=orders, seller_orders=seller_orders)


@login_required
@app.route("/update_order_status", methods=["POST"])
def update_order_status():
    order_id = request.form["order_id"]
    new_status = request.form["new_status"]
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE orders SET status=? WHERE id=?", (new_status, order_id))
    conn.commit()
    conn.close()
    flash("Order status updated successfully.", "success")
    return redirect(url_for("db_manager"))


# ------------------ SELLER DASHBOARD ------------------
@app.route("/seller_orders")
@login_required
@role_required('seller')
def seller_orders():
    """Displays seller-specific orders and statistics."""
    conn = get_db_connection()
    orders = conn.execute('''
        SELECT o.*, p.name AS product_name, u.username AS buyer_name, p.variant AS product_variants
        FROM orders o
        JOIN products p ON o.product_id = p.id
        JOIN users u ON o.buyer_id = u.id
        WHERE p.seller_id=?
        ORDER BY o.created_at DESC
    ''', (session["user_id"],)).fetchall()

    stats = conn.execute('''
        SELECT p.name, COUNT(o.id) as sold_count, SUM(o.amount) as revenue
        FROM orders o
        JOIN products p ON o.product_id = p.id
        WHERE p.seller_id=? AND o.status='success'
        GROUP BY p.name
    ''', (session["user_id"],)).fetchall()
    conn.close()
    return render_template("seller_orders.html", orders=orders, stats=stats)

# ------------------ SELLER-SPECIFIC ROUTES (PRODUCT MANAGEMENT) ------------------

@app.route("/edit_product/<int:product_id>", methods=["GET", "POST"])
@login_required
@role_required("seller")
def edit_product(product_id):
    """
    Allows a seller to edit an existing product.
    GET: Renders the edit form with pre-filled product data.
    POST: Processes the form submission to update the product details.
    """
    conn = get_db_connection()
    product = conn.execute("SELECT * FROM products WHERE id = ? AND seller_id = ?", (product_id, session['user_id'])).fetchone()

    # If product doesn't exist or doesn't belong to the seller, show an error and redirect
    if product is None:
        flash("Product not found or you don't have permission to edit it.", "danger")
        conn.close()
        return redirect(url_for("seller_orders"))

    if request.method == "POST":
        name = request.form.get("name")
        price = request.form.get("price")
        stock = request.form.get("stock")
        color = request.form.get("color")
        size = request.form.get("size")
        variant = request.form.get("variant")
        specifications = request.form.get("specifications")
        
        # Check if a new image file was uploaded
        image_file = request.files.get("image")
        if image_file and image_file.filename != '':
            try:
                # Securely save the new image and update the image_url
                filename = secure_filename(image_file.filename)
                image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                image_file.save(image_path)
                image_url = filename
            except Exception as e:
                flash(f"Error saving image: {e}", "danger")
                conn.close()
                return redirect(url_for("edit_product", product_id=product_id))
        else:
            # If no new image, keep the existing one
            image_url = product['image_url']

        try:
            conn.execute("""
                UPDATE products SET name=?, price=?, stock=?, image_url=?, color=?, size=?, variant=?, specifications=?
                WHERE id=? AND seller_id=?
            """, (name, price, stock, image_url, color, size, variant, specifications, product_id, session['user_id']))
            conn.commit()
            flash("Product updated successfully!", "success")
            return redirect(url_for("seller_orders"))
        except sqlite3.Error as e:
            flash(f"Database error: {e}", "danger")
        finally:
            conn.close()

    conn.close()
    return render_template("edit_product.html", product=product)
@app.route("/delete_product/<int:product_id>", methods=["GET", "POST"])
@login_required
@role_required("seller")
def delete_product(product_id):
    """
    Allows a seller to delete a product.
    GET: Renders a confirmation page.
    POST: Deletes the product from the database.
    """
    conn = get_db_connection()
    product = conn.execute("SELECT * FROM products WHERE id = ? AND seller_id = ?", (product_id, session['user_id'])).fetchone()

    # If product doesn't exist or doesn't belong to the seller, show an error and redirect
    if product is None:
        flash("Product not found or you don't have permission to delete it.", "danger")
        conn.close()
        return redirect(url_for("seller_orders"))

    if request.method == "POST":
        try:
            conn.execute("DELETE FROM products WHERE id = ? AND seller_id = ?", (product_id, session['user_id']))
            conn.commit()
            flash("Product deleted successfully!", "success")
        except sqlite3.Error as e:
            flash(f"Database error: {e}", "danger")
        finally:
            conn.close()
        return redirect(url_for("seller_orders"))

    conn.close()
    return render_template("delete_product.html", product=product)
@app.route("/admin", methods=["GET", "POST"])
@login_required
@role_required("admin")
def admin():
    """
    Admin dashboard to view and manage users and products.
    GET: Displays all users and products.
    POST: Updates a user's role based on form submission.
    """
    conn = get_db_connection()

    if request.method == "POST":
        username = request.form.get("username")
        new_role = request.form.get("role")
        
        if username and new_role:
            try:
                conn.execute("UPDATE users SET role = ? WHERE username = ?", (new_role, username))
                conn.commit()
                flash(f"Successfully updated role for {username} to {new_role}.", "success")
            except sqlite3.Error as e:
                flash(f"Database error: {e}", "danger")
        else:
            flash("Invalid form data for user update.", "danger")

    # This part of the code remains the same, but now it's inside the 'if' block
    users = conn.execute("SELECT username, email, role FROM users").fetchall()
    products = conn.execute("""
        SELECT p.*, u.username AS seller_name
        FROM products p
        JOIN users u ON p.seller_id = u.id
    """).fetchall()

    conn.close()
    return render_template("admin.html", users=users, products=products)
# ------------------ ADMIN PANEL ------------------

@app.route("/delete_user/<int:user_id>", methods=["POST"])
@login_required
@role_required('admin')
def delete_user(user_id):
    """Allows an admin to delete a user."""
    conn = get_db_connection()
    user_to_delete = conn.execute("SELECT username FROM users WHERE id = ?", (user_id,)).fetchone()
    if user_to_delete and user_to_delete['username'] in ['admin', 'dbmanager']:
        flash("Cannot delete a default user.", "danger")
    else:
        conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
        conn.commit()
        flash("User deleted successfully!", "success")
    conn.close()
    return redirect(url_for("admin"))


@app.route("/unanswered_questions")
@login_required
@role_required('admin')
def unanswered_questions():
    """Displays a list of unanswered chatbot questions for the admin to review."""
    conn = get_db_connection()
    questions = conn.execute("SELECT * FROM knowledge_base WHERE answer IS NULL").fetchall()
    conn.close()
    return render_template("unanswered_questions.html", questions=questions)

@app.route("/delete_question/<int:question_id>", methods=["POST"])
@login_required
@role_required(['admin'])
def delete_question(question_id):
    """Deletes an unanswered question from the knowledge base."""
    conn = get_db_connection()
    conn.execute("DELETE FROM knowledge_base WHERE id = ?", (question_id,))
    conn.commit()
    conn.close()
    flash("Question deleted successfully.", "success")
    return redirect(url_for("unanswered_questions"))

@app.route("/answer_question/<int:question_id>", methods=["POST"])
@login_required
@role_required('admin')
def answer_question(question_id):
    """Allows an admin to provide an answer to a question."""
    answer = request.form["answer"]
    sql_query = request.form.get("sql_query")
    conn = get_db_connection()
    conn.execute("UPDATE knowledge_base SET answer = ?, sql_query = ? WHERE id = ?", (answer, sql_query, question_id))
    conn.commit()
    conn.close()
    flash("Question answered successfully!", "success")
    return redirect(url_for("unanswered_questions"))

@app.route("/add_new_question", methods=["POST"])
@login_required
@role_required('admin')
def add_new_question():
    """Allows an admin to manually add a new Q&A pair to the knowledge base."""
    question = request.form["question"]
    answer = request.form["answer"]
    sql_query = request.form.get("sql_query", None)
    conn = get_db_connection()
    try:
        conn.execute("INSERT INTO knowledge_base (question, answer, sql_query) VALUES (?, ?, ?)", (question, answer, sql_query))
        conn.commit()
        flash("New Q&A added successfully!", "success")
    except sqlite3.IntegrityError:
        flash("A question with that text already exists.", "danger")
    finally:
        conn.close()
    return redirect(url_for("answered_questions"))

@app.route("/answered_questions")
@login_required
@role_required('admin')
def answered_questions():
    """Displays a list of answered chatbot questions."""
    conn = get_db_connection()
    questions = conn.execute("SELECT * FROM knowledge_base WHERE answer IS NOT NULL").fetchall()
    conn.close()
    return render_template("answered_questions.html", questions=questions)

@app.route("/delete_answered_questions", methods=["POST"])
@login_required
@role_required('admin')
def delete_all_answered_questions():
    """Allows an admin to delete all answered questions."""
    conn = get_db_connection()
    conn.execute("DELETE FROM knowledge_base WHERE answer IS NOT NULL")
    conn.commit()
    conn.close()
    flash("All answered questions deleted successfully!", "success")
    return redirect(url_for("answered_questions"))

@app.route("/delete_answered_question/<int:question_id>", methods=["POST"])
@login_required
@role_required('admin')
def delete_answered_question(question_id):
    """Allows an admin to delete a single answered question."""
    conn = get_db_connection()
    conn.execute("DELETE FROM knowledge_base WHERE id = ? AND answer IS NOT NULL", (question_id,))
    conn.commit()
    conn.close()
    flash("Question deleted successfully!", "success")
    return redirect(url_for("answered_questions"))

# ------------------ DB MANAGER ACTION ROUTES ------------------

@app.route("/add_column", methods=['POST'])
@login_required
@role_required('dbmanager')
def add_column():
    """Handles the form submission for adding a new column to a table."""
    if request.method == 'POST':
        table_name = request.form['table_name']
        column_name = request.form['column_name']
        column_type = request.form['column_type']

        if not table_name or not column_name or not column_type:
            flash("Please fill in all fields.", "error")
            return redirect(url_for('db_manager'))

        conn = get_db_connection()
        try:
            # Note: This is a simplified example. Parameter substitution is not possible with
            # table and column names in SQLite, so direct string formatting is used.
            # In a production environment, this should be handled with extreme care
            # to prevent SQL injection by validating table and column names against a list of known, safe names.
            conn.execute(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type};")
            conn.commit()
            flash(f"Column '{column_name}' added to table '{table_name}' successfully.", "success")
        except sqlite3.OperationalError as e:
            flash(f"Error adding column: {e}", "error")
        except Exception as e:
            flash(f"An unexpected error occurred: {e}", "error")
        finally:
            conn.close()
            return redirect(url_for('db_manager', table=table_name))

@app.route("/split_table", methods=['POST'])
@login_required
@role_required('dbmanager')
def split_table():
    """Handles the form submission for splitting a table."""
    if request.method == 'POST':
        old_table_name = request.form['old_table_name']
        new_table_name = request.form['new_table_name']
        selected_columns = request.form.getlist('selected_columns')

        if not old_table_name or not new_table_name or not selected_columns:
            flash("Please fill in all fields and select at least one column.", "error")
            return redirect(url_for('db_manager'))

        conn = get_db_connection()
        try:
            # Create the new table with the selected columns
            columns_str = ", ".join([f"{col} TEXT" for col in selected_columns]) # Assuming TEXT type for simplicity
            conn.execute(f"CREATE TABLE {new_table_name} ({columns_str});")
            conn.commit()
            flash(f"Table '{old_table_name}' split and new table '{new_table_name}' created.", "success")
        except sqlite3.OperationalError as e:
            flash(f"Error splitting table: {e}", "error")
        except Exception as e:
            flash(f"An unexpected error occurred: {e}", "error")
        finally:
            conn.close()
            return redirect(url_for('db_manager', table=old_table_name))

@app.route("/create_table", methods=['POST'])
@login_required
@role_required('dbmanager')
def create_table():
    """Handles the form submission for creating a new table."""
    if request.method == 'POST':
        table_name = request.form['table_name']
        column_names = request.form.getlist('column_name[]')
        column_types = request.form.getlist('column_type[]')

        if not table_name or not column_names or not column_types:
            flash("Please fill in the table name and at least one column.", "error")
            return redirect(url_for('db_manager'))

        # Combine column names and types
        columns_with_types = [f"{name} {col_type}" for name, col_type in zip(column_names, column_types)]
        columns_sql = ", ".join(columns_with_types)

        conn = get_db_connection()
        try:
            conn.execute(f"CREATE TABLE {table_name} ({columns_sql});")
            conn.commit()
            flash(f"Table '{table_name}' created successfully.", "success")
        except sqlite3.OperationalError as e:
            flash(f"Error creating table: {e}", "error")
        except Exception as e:
            flash(f"An unexpected error occurred: {e}", "error")
        finally:
            conn.close()
            return redirect(url_for('db_manager'))


@app.route("/execute_query", methods=['POST'])
@login_required
@role_required('dbmanager')
def execute_query():
    """Executes a custom SQL query and returns the result."""
    if request.method == 'POST':
        query = request.form['query']
        conn = get_db_connection()
        try:
            # Execute the query
            cursor = conn.execute(query)
            # Fetch results only for SELECT queries
            if query.strip().upper().startswith('SELECT'):
                columns = [desc[0] for desc in cursor.description]
                query_result = cursor.fetchall()
                # You can store this result in a flash message or a session to display it
                flash("Query executed successfully.", "success")
                # For simplicity, you might want to store the result in the session or pass it to a new template
                # session['query_result'] = {'columns': columns, 'data': query_result}
                # The provided HTML uses a flash message with the 'query_result' category
                flash(f"Query Result: {query_result}", "query_result")
            else:
                conn.commit()
                flash("Query executed successfully.", "success")
        except sqlite3.OperationalError as e:
            flash(f"SQL Error: {e}", "error")
        except Exception as e:
            flash(f"An unexpected error occurred: {e}", "error")
        finally:
            conn.close()
            return redirect(url_for('db_manager'))
# ------------------ PROFILE ROUTE ------------------
@app.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """Allows a user to view and update their profile information."""
    conn = get_db_connection()
    user = conn.execute("SELECT id, username, email, role FROM users WHERE id = ?", (session["user_id"],)).fetchone()
    
    if request.method == "POST":
        new_username = request.form["username"]
        new_email = request.form["email"]
        
        try:
            conn.execute("UPDATE users SET username = ?, email = ? WHERE id = ?",
                         (new_username, new_email, session["user_id"]))
            conn.commit()
            
            # Update the session with the new username to reflect changes immediately
            session["username"] = new_username
            flash("Profile updated successfully!", "success")
            
        except sqlite3.IntegrityError:
            flash("Username or email already exists. Please choose a different one.", "danger")
        except Exception as e:
            flash(f"An error occurred: {e}", "danger")
        finally:
            conn.close()
            return redirect(url_for("profile"))
            
    conn.close()
    return render_template("profile.html", user=user)

# ------------------ DB MANAGER ROUTE (WITH ORDER UPDATE) ------------------

@app.route("/db_manager", methods=["GET", "POST"])
@login_required
@role_required("dbmanager") # Ensure only dbmanager can access
def db_manager():
    """
    Database Manager Dashboard to view tables and update orders.
    GET: Displays the database tables and order data.
    POST: Processes a request to update an order's status.
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    if request.method == "POST":
        order_id = request.form.get("order_id")
        new_status = request.form.get("status")
        if order_id and new_status:
            try:
                conn.execute("UPDATE orders SET status = ? WHERE id = ?", (new_status, order_id))
                conn.commit()
                flash("Order status updated successfully!", "success")
            except sqlite3.Error as e:
                flash(f"Database error: {e}", "danger")
        else:
            flash("Invalid data for order update.", "danger")
        # Redirect to GET request to prevent form resubmission on refresh
        return redirect(url_for("db_manager"))

    # Fetch all tables for the dropdown
    cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
    tables = cursor.fetchall()
    
    selected_table = request.args.get("table")
    columns = []
    table_data = []

    if selected_table:
        cursor.execute(f"PRAGMA table_info({selected_table})")
        columns = cursor.fetchall()
        cursor.execute(f"SELECT * FROM {selected_table}")
        table_data = cursor.fetchall()

    # Fetch all orders to display them on the dashboard
    orders = conn.execute("SELECT * FROM orders").fetchall()
    
    conn.close()

    statuses = ["Payment Pending", "Processing", "Shipped", "In Transit", "Delivered"]

    return render_template(
        "db_dashboard.html",
        tables=tables,
        selected_table=selected_table,
        columns=columns,
        table_data=table_data,
        orders=orders,
        statuses=statuses
    )




if __name__ == "__main__":
    # In a production environment, use a more robust server like Gunicorn or Waitress
    app.run(debug=True, port=8000)
