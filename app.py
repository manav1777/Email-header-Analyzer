import os
import importlib.util
from flask import Flask, render_template, request

# --- Dynamically load header_parser.py ---
project_root = os.path.dirname(os.path.abspath(__file__))
header_parser_path = os.path.join(project_root, "analyzer", "header_parser.py")

spec = importlib.util.spec_from_file_location("header_parser", header_parser_path)
header_parser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(header_parser)

analyze_header = header_parser.analyze_header

LOG_FOLDER = os.path.join(os.getcwd(), "logs")
if not os.path.exists(LOG_FOLDER):
    os.makedirs(LOG_FOLDER)

# --- Flask app ---
app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        header_text = request.form.get("email_header")
        if header_text:
            result = analyze_header(header_text)
    return render_template("index.html", result=result)

# optional root test route
@app.route("/health")
def health():
    return "Email Header Analyzer is running!"

# --- Start app ---
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)