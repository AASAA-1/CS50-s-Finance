import os

from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")

# Make sure API key is set
if not os.environ.get("API_KEY"):
    raise RuntimeError("API_KEY not set")


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    old_stock_prices = db.execute("SELECT * FROM current_stocks WHERE user_id = ?", session["user_id"])
    if old_stock_prices == None:
        return apology("no portfolio found")
    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    # remove this if condition later ?
    if user_cash == None:
        return apology("???")
    # portfolio is the updated stock prices
    for row in old_stock_prices:
        new_price = lookup(row["symbol"])
        db.execute("UPDATE current_stocks SET price = ? WHERE user_id = ? AND symbol = ?",
                   new_price['price'], session["user_id"], new_price["symbol"])

    portfolio = db.execute("SELECT * FROM current_stocks WHERE user_id = ?", session["user_id"])
    return render_template("index.html", portfolio=portfolio, user_cash=user_cash[0]['cash'])


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    if request.method == "GET":
        return render_template("buy.html")

    bought_stock = request.form.get("symbol")
    bought_amount = request.form.get("shares")

    if not bought_amount.replace('.', '', 1).isdigit() or not float(bought_amount).is_integer():
        return apology("You can't purchase partial shares")
    bought_amount = float(bought_amount)

    if bought_stock == None or bought_amount <= 0 or bought_amount == None:
        return apology("Please enter a valid symbol and share amount")
    stock_info = lookup(bought_stock)
    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    if stock_info == None:
        return apology("Stock not found")
    cash_lost = stock_info["price"] * bought_amount
    user_new_cash = user_cash[0]['cash'] - cash_lost
    old_quote_amount = db.execute("SELECT quote_amount FROM current_stockS WHERE user_id = ? AND symbol = ?",
                                  session["user_id"], stock_info["symbol"])

    if cash_lost > user_cash[0]['cash']:
        return apology("Not enough cash")
    db.execute("INSERT INTO history (user_id ,symbol ,quote_amount, price) VALUES (?,?,?,?)",
               session["user_id"], stock_info["symbol"], str(bought_amount), stock_info["price"])

    symbol_checker = db.execute("SELECT * FROM current_stocks WHERE symbol = ? AND user_id = ?",
                                stock_info["symbol"], session["user_id"])

    if len(symbol_checker) != 0:
        new_quote_amount = old_quote_amount[0]['quote_amount'] + bought_amount
        db.execute("UPDATE current_stocks SET quote_amount = ? WHERE user_id = ? AND symbol = ?",
                   new_quote_amount, session["user_id"], stock_info["symbol"])
    else:
        db.execute("INSERT INTO current_stocks (user_id ,symbol ,quote_name ,quote_amount, price) VALUES (?,?,?,?,?)",
                   session["user_id"], stock_info["symbol"], stock_info["name"], bought_amount, stock_info["price"])
    db.execute("UPDATE users SET cash = ? WHERE id = ?", user_new_cash, session["user_id"])
    # copypasting "/" route code so I can get a proper template render
    old_stock_prices = db.execute("SELECT * FROM current_stocks WHERE user_id = ?", session["user_id"])
    if old_stock_prices == None:
        return apology("no portfolio found")
    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    if user_cash == None:
        return apology("???")
    # portfolio is the updated stock prices
    for row in old_stock_prices:
        new_price = lookup(row["symbol"])
        db.execute("UPDATE current_stocks SET price = ? WHERE user_id = ? AND symbol = ?",
                   new_price['price'], session["user_id"], new_price["symbol"])

    portfolio = db.execute("SELECT * FROM current_stocks WHERE user_id = ?", session["user_id"])
    alert = "bought " + str(bought_amount) + " stocks of " + stock_info["symbol"]
    return render_template("index.html", portfolio=portfolio, user_cash=user_cash[0]['cash'], alert=alert)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    history = db.execute("SELECT * FROM history WHERE user_id = ?", session["user_id"])
    if len(history) == 0:
        return render_template("nohistory.html")

    return render_template("history.html", history=history)


@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = ?", request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    if request.method == "GET":
        return render_template("quote.html")
    else:
        inputtedquote = request.form.get("symbol")
        stock_info = lookup(inputtedquote)
        if stock_info == None:
            return apology("Stock not found")
        return render_template("quoteinfo.html", quote="A share of " + stock_info['name'] + " (" + stock_info["symbol"] + ")" + " costs " + usd(stock_info["price"]))


@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "GET":
        return render_template("register.html")
    else:
        username = request.form.get("username")
        password = request.form.get("password")
        passwordconfirmation = request.form.get("confirmation")
        if len(username) == 0 or len(password) == 0 or len(passwordconfirmation) == 0:
            return apology("invalid username or password")
        if password != passwordconfirmation:
            return apology("Password and Password confirmation don't match")
        usernamecheck = db.execute("SELECT * FROM users WHERE username = ?", username)
        if len(usernamecheck) != 0:
            return apology("Username already registered")

        hashedpassword = generate_password_hash(password, method="pbkdf2:sha256", salt_length=8)
        db.execute("INSERT INTO users (username, hash) VALUES (?, ?)", username, hashedpassword)
        return render_template("login.html")
        # clean up register.html layout


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    if request.method == "GET":
        symbols = db.execute("SELECT symbol FROM current_stocks WHERE user_id = ?", session["user_id"])
        return render_template("sell.html", symbols=symbols)

    symbol = request.form.get("symbol")
    shares = request.form.get("shares")
    if symbol == None or shares == None or shares.isdigit() == False:
        return apology("Don't leave any fields empty")

    stock_info = lookup(symbol)

    owned_amount = db.execute(
        "SELECT symbol, quote_amount FROM current_stocks WHERE user_id = ? AND symbol = ?", session["user_id"], symbol)
    if len(owned_amount) == 0 or owned_amount[0]["quote_amount"] == 0:
        return apology("You don't own any of this share")

    shares = int(shares)
    if shares <= 0:
        return apology("Please enter a valid share amount")

    shares_post_transaction = owned_amount[0]["quote_amount"] - shares
    if shares > owned_amount[0]["quote_amount"]:
        return apology("You're trying to sell more than you own")
    portfolio = db.execute("SELECT * FROM current_stocks WHERE user_id = ?", session["user_id"])
    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])
    if user_cash == None or portfolio == None:
        return apology("User account not found")
    cash_owed = stock_info["price"] * shares
    db.execute("UPDATE users SET cash = cash + ? WHERE id = ?", cash_owed, session["user_id"])
    db.execute("INSERT INTO history (user_id ,symbol ,quote_amount, price) VALUES (?,?,?,?)",
               session["user_id"], stock_info["symbol"], "-" + str(shares), stock_info["price"])
    if shares_post_transaction == 0:
        db.execute("DELETE FROM current_stocks WHERE user_id = ? AND symbol = ?", session["user_id"], stock_info["symbol"])
    else:
        db.execute("UPDATE current_stocks SET quote_amount = ? WHERE user_id = ? AND symbol = ?",
                   shares_post_transaction, session["user_id"], stock_info["symbol"])
    old_stock_prices = db.execute("SELECT * FROM current_stocks WHERE user_id = ?", session["user_id"])
    if old_stock_prices == None:
        return apology("no portfolio found")
    user_cash = db.execute("SELECT cash FROM users WHERE id = ?", session["user_id"])

    if user_cash == None:
        return apology("???")
    # portfolio is the updated stock prices
    for row in old_stock_prices:
        new_price = lookup(row["symbol"])
        db.execute("UPDATE current_stocks SET price = ? WHERE user_id = ? AND symbol = ?",
                   new_price['price'], session["user_id"], new_price["symbol"])

    portfolio = db.execute("SELECT * FROM current_stocks WHERE user_id = ?", session["user_id"])
    alert = "sold " + str(shares) + " stocks of " + stock_info["symbol"]
    return render_template("index.html", portfolio=portfolio, user_cash=user_cash[0]['cash'], alert=alert)

