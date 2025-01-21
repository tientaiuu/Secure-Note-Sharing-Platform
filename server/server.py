import os
from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template
from utils import hash_password, verify_password, generate_note_url
import json

# Nạp các biến môi trường từ tệp .env
load_dotenv()

app = Flask(__name__)

# Lấy SECRET_KEY từ biến môi trường
SECRET_KEY = os.getenv("SECRET_KEY")
print("SECRET KEY: ",SECRET_KEY)
app.config['SECRET_KEY'] = SECRET_KEY

@app.route('/get-secret', methods = ['GET'])
def get_secret():
    if app.config.get('SECRET_KEY'):
        return jsonify({"secretKey": app.config['SECRET_KEY']}), 200
    else:
        return jsonify({"error": "Secret key not found"}), 500
    
# Đường dẫn đến database
DATABASE_PATH = "./server/database.json"

# Đọc database
def read_database():
    if not os.path.exists(DATABASE_PATH):
        return {"users": {}, "notes": {}}
    with open(DATABASE_PATH, "r") as f:
        return json.load(f)

# Ghi vào database
def write_database(data):
    with open(DATABASE_PATH, "w") as f:
        json.dump(data, f, indent=4)

def update_note_in_db(note_id, content):
    db = read_database()
    if note_id in db["notes"]:
        db["notes"][note_id]["content"] = content
        write_database(db)
        return True
    return False

@app.route('/')
def index():
    return render_template('index.html')

    
    
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        data = request.json
        username = data["username"]
        password = data["password"]

        db = read_database()
        if username in db["users"]:
            return jsonify({"error": "User already exists"}), 400

        db["users"][username] = hash_password(password)
        write_database(db)
        return jsonify({"message": "User registered successfully"}), 201
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        data = request.json
        username = data["username"]
        password = data["password"]

        db = read_database()
        if username not in db["users"]:
            return jsonify({"error": "User not found"}), 404

        if not verify_password(password, db["users"][username]):
            return jsonify({"error": "Invalid credentials"}), 401

        return jsonify({"message": "Login successful"}), 200
    return render_template('login.html')

@app.route("/dashboard", methods=['GET', 'POST'])
def dashboard():
    return render_template('dashboard.html')

@app.route("/create-note", methods=['GET', 'POST'])
def create_note():
    if request.method == 'POST':
        data = request.json
        username = data["username"]
        note_content = data["note_content"]

        db = read_database()
        print(db)
        print(data)
        if username not in db["users"]:
            return jsonify({"error": "User not found"}), 404

        note_id = generate_note_url()
        if "notes" not in db:
            db["notes"] = {}

        db["notes"][note_id] = {"owner": username, "content": note_content}
        write_database(db)
        return jsonify({"message": "Note created", "note_id": note_id}), 201
    return render_template('create_note.html')

@app.route("/view-notes", methods=["GET", "POST"])
def view_notes():
    if request.method == "POST":
        if request.is_json:
            data = request.json
        else:
            data = request.form

        username = data.get("username")
        if not username:
            return jsonify({"error": "Username is required"}), 400

        db = read_database()
        user_notes = [
            {"note_id": note_id, "content": note["content"]}
            for note_id, note in db["notes"].items()
            if note["owner"] == username
        ]

        if not user_notes:
            return jsonify({"message": "No notes found for this user"}), 404

        return jsonify({"notes": user_notes}), 200

    return render_template("view_notes.html")

@app.route("/delete-note", methods=["POST"])
def delete_note():
    data = request.json
    username = data["username"]
    note_id = data["note_id"]
    db = read_database()

    if not username or not note_id:
        return jsonify({"success": False, "message": "Thiếu thông tin username hoặc note_id"}), 400
    try:
        if note_id in db["notes"]:
            note = db["notes"][note_id]
            if note["owner"] == username:
                del db["notes"][note_id]

                write_database(db)
                
                return jsonify({"success": True, "message": "Ghi chú đã được xóa thành công."}), 200
            else:
                return jsonify({"success": False, "message": "Bạn không có quyền xóa ghi chú này."}), 403
        else:
            return jsonify({"success": False, "message": "Không tìm thấy ghi chú."}), 404

    except Exception as e:
        return jsonify({"success": False, "message": f"Lỗi trong quá trình xử lý: {str(e)}"}), 500

@app.route("/edit-note", methods=["POST"])
def edit_note():
    data = request.json
    note_id = data["note_id"]
    content = data["content"]
    username = data["username"]

    if note_id and content and username:
        # Giải mã và lưu lại nội dung ghi chú (nếu cần)
        try:
            # Lưu ghi chú mới vào cơ sở dữ liệu
            update_note_in_db(note_id, content)
            return jsonify({"success": True})
        except Exception as e:
            return jsonify({"success": False, "message": str(e)})
    return jsonify({"success": False, "message": "Dữ liệu không hợp lệ"})

# @app.route("/share-note", method=["Post", "Get"])
# def share_note():
#     data = request.json
#     note_id = data["note_id"]
#     content = data["content"]
#     username = data["username"]
    
    
if __name__ == "__main__":
    app.run(debug=True, port=5000)
