import os, sqlite3, random
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import razorpay

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "supersecret")

UPLOAD_FOLDER = 'static/uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Razorpay client (Test keys)
razorpay_client = razorpay.Client(auth=("rzp_test_RJbeRtchCzjRnl", "U1n6sacDbHO3CDCUstNBCs4C"))

DB_NAME = 'database.db'

# ------------------ DATABASE ------------------
def get_db_connection():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        email TEXT UNIQUE,
        password TEXT NOT NULL,
        role TEXT DEFAULT 'user'
    )''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        seller_id INTEGER,
        name TEXT NOT NULL,
        price REAL NOT NULL,
        image TEXT,
        FOREIGN KEY (seller_id) REFERENCES users(id)
    )''')
    cursor.execute('''
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        product_id INTEGER,
        buyer_id INTEGER,
        amount REAL,
        payment_id TEXT,
        status TEXT,
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (product_id) REFERENCES products(id),
        FOREIGN KEY (buyer_id) REFERENCES users(id)
    )''')
    # Default admin
    cursor.execute("SELECT * FROM users WHERE username='admin'")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO users (username,email,password,role) VALUES (?,?,?,?)",
                       ("admin","admin@example.com",generate_password_hash("admin123"),"admin"))
    cursor.execute("SELECT * FROM users WHERE username='dbmanager'")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO users (username,email,password,role) VALUES (?,?,?,?)",
                       ("dbmanager","22052204@kiit.ac.in",generate_password_hash("dbpass123"),"dbmanager"))
    conn.commit()
    conn.close()

init_db()

# ------------------ AUTH ------------------
@app.route("/signup", methods=["GET","POST"])
def signup():
    if request.method=="POST":
        username = request.form["username"]
        email = request.form["email"]
        password = generate_password_hash(request.form["password"])
        conn = get_db_connection()
        try:
            conn.execute("INSERT INTO users (username,email,password) VALUES (?,?,?)",
                         (username,email,password))
            conn.commit()
            flash("Signup successful! Please login.")
            return redirect(url_for("login"))
        except sqlite3.IntegrityError:
            flash("Username or email already exists!")
        finally:
            conn.close()
    return render_template("signup.html")

@app.route("/login", methods=["GET","POST"])
def login():
    if request.method=="POST":
        username = request.form["username"]
        password = request.form["password"]
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username=?",(username,)).fetchone()
        conn.close()
        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            flash("Logged in successfully!")
            return redirect(url_for("home"))
        else:
            flash("Invalid credentials!")
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully!")
    return redirect(url_for("login"))

# ------------------ PASSWORD RESET ------------------
@app.route("/forgot", methods=["GET","POST"])
def forgot():
    if request.method=="POST":
        email = request.form["email"]
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE email=?",(email,)).fetchone()
        conn.close()
        if user:
            otp = str(random.randint(1000,9999))
            session["otp"] = otp
            session["reset_email"] = email
            flash(f"OTP sent to {email}: {otp}")
            return redirect(url_for("verify_otp"))
        else:
            flash("Email not registered!")
    return render_template("forgot.html")

@app.route("/verify_otp", methods=["GET","POST"])
def verify_otp():
    if request.method=="POST":
        entered = request.form["otp"]
        if entered==session.get("otp"):
            return redirect(url_for("reset_password"))
        else:
            flash("Invalid OTP!")
    return render_template("verify.html")

@app.route("/reset_password", methods=["GET","POST"])
def reset_password():
    if request.method=="POST":
        new_pass = generate_password_hash(request.form["password"])
        email = session.get("reset_email")
        conn = get_db_connection()
        conn.execute("UPDATE users SET password=? WHERE email=?",(new_pass,email))
        conn.commit()
        conn.close()
        session.pop("otp",None)
        session.pop("reset_email",None)
        flash("Password reset successful!")
        return redirect(url_for("login"))
    return render_template("reset.html")

# ------------------ HOME ------------------
@app.route("/")
def home():
    conn = get_db_connection()
    products = conn.execute("SELECT * FROM products").fetchall()
    conn.close()
    return render_template("home.html", products=products, user=session.get("username"), role=session.get("role"))

# ------------------ ADD PRODUCT ------------------
@app.route("/add_product", methods=["GET","POST"])
def add_product():
    if "user_id" not in session:
        flash("Login first!")
        return redirect(url_for("login"))
    if request.method=="POST":
        name = request.form["name"]
        price = float(request.form["price"])
        image = request.files["image"]
        filename = None
        if image:
            filename = secure_filename(image.filename)
            image.save(os.path.join(app.config["UPLOAD_FOLDER"],filename))
        conn = get_db_connection()
        conn.execute("INSERT INTO products (seller_id,name,price,image) VALUES (?,?,?,?)",
                     (session["user_id"],name,price,filename))
        conn.commit()
        conn.close()
        flash("Product added successfully!")
        return redirect(url_for("add_product"))
    return render_template("add_product.html")

# ... (existing imports and code) ...

# ------------------ CHATBOT ------------------
@app.route("/chatbot", methods=["POST"])
def chatbot():
    data = request.get_json()
    user_message = data.get("message", "").lower().strip()
    
    conn = get_db_connection()
    response_message = "I'm sorry, I can only help you with product-related queries. Try asking about products or features."
    products = []
    
    # ------------------ GENERAL QUESTIONS (10) ------------------
    if any(q in user_message for q in ["hi", "hello", "hey", "what's up", "greetings", "good morning", "good evening", "how are you", "what can you do"]):
        response_message = "Hello! I am LocalMart's AI assistant. I can help you find products, answer questions about the site, and provide details about your account. What can I help you with?"
    
    elif any(q in user_message for q in ["how can i signup", "how to register", "create account", "i want to join", "new user", "how do i create an account"]):
        response_message = "You can create a new account by clicking the 'Signup' link in the navigation bar. You just need a username, email, and password."
        
    elif any(q in user_message for q in ["how can i login", "how to login", "sign in", "i want to log in", "already have an account"]):
        response_message = "To log in, click the 'Login' link at the top of the page. You'll need your username and password."
        
    elif any(q in user_message for q in ["forgot password", "reset password", "lost my password", "can't access my account"]):
        response_message = "If you've forgotten your password, click the 'Forgot Password?' link on the login page. We'll send an OTP to your registered email to help you reset it."
        
    elif any(q in user_message for q in ["who is the admin", "what is a dbmanager", "what is an admin", "admin dashboard", "dbmanager dashboard"]):
        response_message = "The 'Admin Dashboard' is for site administrators to manage users and their roles (user, seller, admin). The 'dbmanager' role is for database-related tasks. These are powerful roles for site management."
        
    elif any(q in user_message for q in ["how to become a seller", "i want to sell something", "add product", "list an item", "upload product", "become a vendor"]):
        response_message = "To become a seller, first log in to your account. Then, navigate to the 'Add Product' page to upload your product details and an image. Your account role will automatically be a seller once you add your first product."

    elif any(q in user_message for q in ["how can i buy", "how to purchase", "buy a product", "how to checkout"]):
        response_message = "To buy a product, simply click the 'Buy' button next to the item you want. This will take you to a secure checkout page where you can complete your payment."

    elif any(q in user_message for q in ["my orders", "order history", "past purchases", "what did i buy", "check my orders"]):
        response_message = "You can view all your past purchases by clicking the 'My Orders' link in the navigation bar after you have logged in."

    elif any(q in user_message for q in ["seller orders", "my sales", "who bought my products", "what did i sell"]):
        response_message = "If you are a seller, you can track all the orders for your products by clicking the 'Seller Orders' link in the navigation bar."

    elif any(q in user_message for q in ["cancel order", "replace product", "return product", "exchange item"]):
        response_message = "Currently, our platform does not support order cancellation, replacement, or returns. All sales are final. Please review the product carefully before purchasing."

    # ------------------ PRODUCT-RELATED QUESTIONS (10) ------------------
    # Search by price
    elif "under" in user_message or "less than" in user_message:
        try:
            import re
            price_match = re.search(r'(\d+(\.\d+)?)', user_message)
            if price_match:
                max_price = float(price_match.group())
                products = conn.execute("SELECT * FROM products WHERE price <= ?", (max_price,)).fetchall()
                if products:
                    response_message = f"Here are some products under ₹{max_price}:"
                else:
                    response_message = f"No products found under ₹{max_price}."
            else:
                response_message = "I couldn't find a price in your message. Please try 'show me products under 500'."
        except (ValueError, IndexError):
            response_message = "I couldn't understand the price. Please try 'show me products under 500'."

    # Search for a product's cost
    elif "cost" in user_message or "price" in user_message or "how much" in user_message:
        # Extract product name from message
        product_name = user_message.replace("what is the", "").replace("of", "").replace("the cost", "").replace("cost", "").replace("price", "").replace("how much", "").strip()
        product = conn.execute("SELECT * FROM products WHERE name LIKE ?", ('%' + product_name + '%',)).fetchone()
        if product:
            response_message = f"The price of {product['name']} is ₹{product['price']}."
        else:
            response_message = f"I'm sorry, I couldn't find the price for {product_name}."

    # General product search
    elif "show me" in user_message or "find" in user_message or "search for" in user_message or "list" in user_message:
        search_query = user_message.replace("show me", "").replace("find", "").replace("search for", "").replace("list", "").strip()
        products = conn.execute("SELECT * FROM products WHERE name LIKE ?", ('%' + search_query + '%',)).fetchall()
        if products:
            response_message = f"Here's what I found for '{search_query}':"
        else:
            response_message = "Sorry, I couldn't find any products matching that description."
            
    # Check for image info
    elif any(q in user_message for q in ["photo of", "image of", "show me a picture of"]):
        product_name = user_message.replace("photo of", "").replace("image of", "").replace("show me a picture of", "").strip()
        product = conn.execute("SELECT * FROM products WHERE name LIKE ?", ('%' + product_name + '%',)).fetchone()
        if product and product['image']:
            # This is where we tell the chatbot to show the image on the frontend.
            # We will send the image filename back in the JSON response.
            response_message = f"Here is a photo of the {product['name']}."
            products.append(product) # Add the product to the list to show its image
        elif product:
            response_message = f"Sorry, there is no image available for {product['name']}."
        else:
            response_message = f"I couldn't find a product named {product_name}."

    # Fallback/Default response
    else:
        response_message = "I'm sorry, I don't understand that request. Please try asking about products or site features."
    
    conn.close()

    return {"message": response_message, "products": [dict(p) for p in products]}



# ------------------ BUY PRODUCT ------------------
@app.route("/buy/<int:product_id>")
def buy(product_id):
    conn = get_db_connection()
    product = conn.execute("SELECT * FROM products WHERE id=?",(product_id,)).fetchone()
    conn.close()
    if not product:
        flash("Product not found!")
        return redirect(url_for("home"))
    order_amount = int(product["price"]*100)
    razorpay_order = razorpay_client.order.create(dict(amount=order_amount, currency="INR", payment_capture="1"))
    return render_template("checkout.html", product=product, razorpay_order=razorpay_order)

@app.route("/payment_success", methods=["POST"])
def payment_success():
    payment_id = request.form["razorpay_payment_id"]
    product_id = request.form["product_id"]
    conn = get_db_connection()
    product = conn.execute("SELECT * FROM products WHERE id=?",(product_id,)).fetchone()
    if product:
        conn.execute("INSERT INTO orders (product_id,buyer_id,amount,payment_id,status) VALUES (?,?,?,?,?)",
                     (product_id,session.get("user_id"),product["price"],payment_id,"Success"))
        conn.commit()
    conn.close()
    flash("Payment successful!")
    return redirect(url_for("home"))

# ------------------ ORDER HISTORY ------------------
@app.route("/my_orders")
def my_orders():
    if "user_id" not in session:
        flash("Login first!")
        return redirect(url_for("login"))
    conn = get_db_connection()
    orders = conn.execute('''
        SELECT o.id, o.amount, o.payment_id, o.status, o.created_at, p.name AS product_name
        FROM orders o
        JOIN products p ON o.product_id = p.id
        WHERE o.buyer_id=?
        ORDER BY o.created_at DESC
    ''',(session["user_id"],)).fetchall()
    conn.close()
    return render_template("my_orders.html", orders=orders)

@app.route("/seller_orders")
def seller_orders():
    if "user_id" not in session:
        flash("Login first!")
        return redirect(url_for("login"))
    conn = get_db_connection()
    orders = conn.execute('''
        SELECT o.id, o.amount, o.payment_id, o.status, o.created_at, p.name AS product_name, u.username AS buyer_name
        FROM orders o
        JOIN products p ON o.product_id = p.id
        JOIN users u ON o.buyer_id = u.id
        WHERE p.seller_id=?
        ORDER BY o.created_at DESC
    ''',(session["user_id"],)).fetchall()
    
    # Statistics for seller
    stats = conn.execute('''
        SELECT p.name, COUNT(o.id) as sold_count, SUM(o.amount) as revenue
        FROM orders o
        JOIN products p ON o.product_id = p.id
        WHERE p.seller_id=?
        GROUP BY p.name
    ''',(session["user_id"],)).fetchall()
    conn.close()
    return render_template("seller_orders.html", orders=orders, stats=stats)

# ------------------ ADMIN ------------------
@app.route("/admin", methods=["GET","POST"])
def admin():
    if "role" not in session or session["role"] not in ["admin","dbmanager"]:
        return "Access Denied!"
    conn = get_db_connection()
    if request.method=="POST":
        # Update user email or role
        username = request.form["username"]
        new_email = request.form["email"]
        new_role = request.form["role"]
        conn.execute("UPDATE users SET email=?, role=? WHERE username=?",
                     (new_email,new_role,username))
        conn.commit()
        flash(f"{username} updated successfully!")
    users = conn.execute("SELECT username,email,role FROM users").fetchall()
    conn.close()
    return render_template("admin.html", users=users)

# ------------------ RUN ------------------
if __name__=="__main__":
    app.run(debug=True)
