import os
import importlib.util
from flask import Flask, render_template, request

project_root = os.path.dirname(os.path.abspath(__file__))
header_parser_path = os.path.join(project_root, "analyzer", "header_parser.py")

spec = importlib.util.spec_from_file_location("header_parser", header_parser_path)
header_parser = importlib.util.module_from_spec(spec)
spec.loader.exec_module(header_parser)

analyze_header = header_parser.analyze_header

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    input_text = ""

    if request.method == "POST":
        input_text = request.form.get("emailheader")
        if input_text:
            result = analyze_header(input_text)

    return render_template("index.html", result=result, input_text=input_text)

@app.route("/health")
def health():
    return "running"

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port)