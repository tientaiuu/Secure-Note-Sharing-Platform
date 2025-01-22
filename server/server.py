import os
from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template
from utils import hash_password, verify_password, generate_note_url
import json
import secrets
import time

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

@app.route("/create-temp-link", methods=["POST"])
def create_temp_link():
    # get dữ liệu người dùng
    data = request.get_json()
    note_id = data.get("note_id")
    duration_minutes = data.get("duration_minutes", 60)
    username = data.get("username")

    db = read_database()

    # Kiểm tra note_id hợp lệ, user có phải owner không
    if note_id not in db["notes"]:
        return jsonify({"error": f"Note {note_id} not found"}), 404

    note_data = db["notes"][note_id]
    if note_data["owner"] != username:
        return jsonify({"error": "You are not the owner of this note"}), 403

    # Tính thời gian hết hạn link
    try:
        duration_minutes = int(duration_minutes)
    except ValueError:
        duration_minutes = 60
    expiry_time = int(time.time() + duration_minutes*60)

    # Sinh token
    token = secrets.token_urlsafe(32)

    # Lưu vào db
    if "shared_links" not in db:
        db["shared_links"] = {}
    db["shared_links"][token] = {
        "note_id": note_id,
        "expiry": expiry_time
    }
    write_database(db)

    share_url = f"http://127.0.0.1:5000/share/{token}"
    return jsonify({"share_url": share_url, "expiry": expiry_time}), 200

@app.route("/share/<token>", methods=["GET"])
def share_note(token):
    
    db = read_database()
    shared_info = db.get("shared_links", {}).get(token)
    


    if not shared_info:
        return render_template("notFound.html"), 410
        
    # Kiểm tra thời gian chia sẻ
    now = int(time.time())
    if now > shared_info["expiry"]:
        del db["shared_links"][token]
        write_database(db)
        return render_template("expired.html"), 410

    expiry = now + shared_info["expiry"]
    note_id = shared_info["note_id"]
    note_data = db["notes"].get(note_id)
    owner = note_data["owner"]
    if not note_data:
        return "Không tìm thấy ghi chú", 404

    # Lấy ciphertext
    ciphertext = note_data["content"]
    # Render template note_url.html, truyền token & ciphertext
    return render_template("note_url.html",
                           owner = owner,
                           expiry = expiry,
                           note_id=note_id,
                           ciphertext=ciphertext)

@app.route("/revoke-link", methods=["POST"])
def revoke_link():
    data = request.json
    token = data.get("token")
    username = data.get("username")

    db = read_database()
    shared_info = db.get("shared_links", {}).get(token, None)
    if not shared_info:
        return jsonify({"error": "Token không tồn tại hoặc đã xóa"}), 404

    # Kiểm tra chủ sở hữu
    note_id = shared_info["note_id"]
    note_data = db["notes"].get(note_id)
    if not note_data:
        return jsonify({"error": "Note không tồn tại"}), 404

    if note_data["owner"] != username:
        return jsonify({"error": "Bạn không phải chủ ghi chú"}), 403

    # Xóa token
    del db["shared_links"][token]
    write_database(db)
    return jsonify({"message": "Link chia sẻ đã bị hủy"}), 200

  

# @app.route("/share-note", methods=['GET', 'POST'])
# def share_note():
#     if request.method == 'POST':
#         data = request.json
#         if not data:
#             return jsonify({"error": "No JSON data"}), 400
        
#         from_user = data.get("from_user")
#         to_user   = data.get("to_user")
#         note_id   = data.get("note_id")

#         if not (from_user and to_user and note_id):
#             return jsonify({"error": "Missing from_user / to_user / note_id"}), 400

#         db = read_database()

#         # Kiểm tra from_user có tồn tại không
#         if from_user not in db["users"]:
#             return jsonify({"error": f"User {from_user} not found"}), 404

#         # Kiểm tra to_user có tồn tại không
#         if to_user not in db["users"]:
#             return jsonify({"error": f"User {to_user} not found"}), 404

#         # Kiểm tra note_id có tồn tại không
#         if note_id not in db["notes"]:
#             return jsonify({"error": f"Note {note_id} not found"}), 404

#         note_data = db["notes"][note_id]

#         # Thêm to_user vào danh sách shared_with
#         if "shared_with" not in note_data:
#             note_data["shared_with"] = []

#         if to_user not in note_data["shared_with"]:
#             note_data["shared_with"].append(to_user)

#         # Ghi ngược lại vào DB
#         db["notes"][note_id] = note_data
#         write_database(db)
        
#         # Kiểm tra DB, update shared_with, v.v.
#         return jsonify({"message": f"Note {note_id} has been shared with {to_user}"}), 200
    
#     return render_template("share_note.html")


    
@app.route("/view-notes", methods=["GET", "POST"])
def view_notes():
    if request.method == "POST":
        # Lấy dữ liệu request
        if request.is_json:
            data = request.json
        else:
            data = request.form

        username = data.get("username")
        if not username:
            return jsonify({"error": "Username is required"}), 400

        db = read_database()

        # 1) Tìm note mà user sở hữu hoặc được chia sẻ
        user_notes = []
        for note_id, note_data in db["notes"].items():
            if note_data["owner"] == username or (note_data.get("shared_with") and username in note_data["shared_with"]):
                user_notes.append({
                    "note_id": note_id,
                    "content": note_data["content"]
                })

        if not user_notes:
            return jsonify({"message": "No notes found for this user"}), 404

        # 2) Tạo dict để lưu danh sách token theo note
        note_tokens = {}
        # Khởi tạo mảng rỗng cho mỗi note_id
        for note in user_notes:
            note_tokens[note["note_id"]] = []

        # 3) Duyệt db["shared_links"] để tìm token nào match note_id
        shared_links = db.get("shared_links", {})
        now = time.time()
        for token, info in shared_links.items():
            note_id = info["note_id"]
            # Nếu note_id thuộc tập note của user + link chưa hết hạn
            if note_id in note_tokens and now < info["expiry"]:
                note_tokens[note_id].append(token)

        # 4) Trả về JSON
        # - "notes": mảng note
        # - "tokens": dict { note_id: [token1, token2, ...] }
        return jsonify({
            "notes": user_notes,
            "tokens": note_tokens
        }), 200

    # Nếu GET, render template
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

if __name__ == "__main__":
    app.run(debug=True, port=5000)
