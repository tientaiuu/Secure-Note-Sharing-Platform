from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template,session, redirect, url_for
from utils import hash_password, verify_password, generate_note_url
import secrets, time, json, os, hashlib, hmac

# Nạp các biến môi trường từ tệp .env
load_dotenv()

app = Flask(__name__)

P = 23  # Giá trị đơn giản hóa, cần thay bằng số nguyên tố lớn hơn trong thực tế
G = 5

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
        
        session["username"] = username

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
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "No data provided"}), 400
        
        note_id = data.get("note_id")
        duration_minutes = int(data.get("duration_minutes", 60))
        client_public_key = int(data.get("client_public_key"))

        db = read_database()

        # Kiểm tra xem ghi chú có tồn tại không
        if note_id not in db.get("notes", {}):
            return jsonify({"error": "Note không tồn tại"}), 404

        expiry_time = int(time.time() + duration_minutes * 60)

        if "shared_links" not in db:
            db["shared_links"] = {}
        
        if "KEYS" not in db:
            db["KEYS"] = {}

        if note_id in db["KEYS"]:
            # Lấy khóa riêng tư đã lưu
            server_private_key = db["KEYS"][note_id]["server_private_key"]
            server_public_key = db["KEYS"][note_id]["server_public_key"]
        else:
            # Tạo khóa mới và lưu vào database
            server_private_key = secrets.randbelow(P)
            server_public_key = pow(G, server_private_key, P)
    
            db["KEYS"][note_id] = {
                "server_private_key": server_private_key,
                "server_public_key": server_public_key,
                "client_public_key":client_public_key      
            }

        # Tính shared secret với khóa công khai của client
        shared_secret = pow(client_public_key, server_private_key, P)
        session_key = hashlib.sha256(str(shared_secret).encode()).hexdigest()

        print(f"[DEBUG] client public key: {client_public_key}")
        print(f"[DEBUG] server prviate key: {server_private_key}")
        print(f"[DEBUG] Shared Secret: {shared_secret}")
        print(f"[DEBUG] Calculated Session Key: {session_key}")

        # Tạo token chia sẻ
        token = secrets.token_urlsafe(16)

        db["shared_links"][token] = {
            "note_id": note_id,
            "expiry": expiry_time,
            "session_key": session_key,
            "server_public_key": server_public_key
        }

        write_database(db)

        return jsonify({
            "share_url": f"http://127.0.0.1:5000/share/{token}",
            "server_public_key": server_public_key,
            "expiry": expiry_time
        })
    
    except ValueError:
        return jsonify({"error": "Invalid input data"}), 400
    
    except Exception as e:
        app.logger.error(f"Error processing request: {e}")
        return jsonify({"error": "Internal Server Error"}), 500

@app.route("/share/<token>", methods=["GET"])
def share_note(token):
    # Kiểm tra xem người dùng đã đăng nhập hay chưa
    if "username" not in session:
        return redirect(url_for("login"))  # Chuyển hướng đến trang đăng nhập nếu chưa đăng nhập

    db = read_database()
    shared_info = db.get("shared_links", {}).get(token)

    if not shared_info:
        db["shared_links"].pop(token, None)  # Xóa liên kết đã hết hạn
        write_database(db)
        return render_template("expired.html"), 410

    # Kiểm tra nếu thông tin khóa tồn tại
    key_info = db.get("KEYS", {}).get(shared_info["note_id"], None)
    if not key_info:
        return jsonify({"error": "Khóa không tồn tại"}), 404

    owner = session["username"]

    return render_template(
        "note_url.html",
        token=token,
        owner=owner,
        note_id=shared_info["note_id"],
        server_public_key=key_info["server_public_key"],  # Đảm bảo dùng đúng khóa key
        client_public_key=key_info["client_public_key"]
    )
    
@app.route("/get-note/<token>", methods=["POST"])
def get_shared_note(token):
    db = read_database()
    shared_info = db.get("shared_links", {}).get(token)

    if not shared_info or int(time.time()) > shared_info["expiry"]:
        db["shared_links"].pop(token, None)  # Xóa liên kết đã hết hạn
        write_database(db)
        return render_template("expired.html"), 410

    key_info = db.get("KEYS", {}).get(shared_info["note_id"], None)
    if not key_info:
        return jsonify({"error": "Không tìm thấy khóa server của ghi chú #"+ shared_info["note_id"]}), 404

    client_public_key = key_info.get("client_public_key")
    if not client_public_key:
        return jsonify({"error": "Không tìm thấy khóa công khai của client"}), 403

    try:
        client_public_key = int(client_public_key)
    except ValueError:
        return jsonify({"error": "Khóa công khai không hợp lệ"}), 403


    # Tính shared secret theo đúng thuật toán Diffie-Hellman
    server_private_key = key_info["server_private_key"]
    shared_secret = pow(client_public_key, server_private_key, P)
    session_key = hashlib.sha256(str(shared_secret).encode()).hexdigest()
    
    print(f"--------\n[DEBUG] client public key: {client_public_key}")
    print(f"[DEBUG] server private key: {server_private_key}")
    print(f"[DEBUG] Shared Secret: {shared_secret}")
    print(f"[DEBUG] Calculated Session Key: {session_key}")


    if session_key != shared_info["session_key"]:
        return jsonify({"error": "Sai khóa phiên"}), 403

    note_id = shared_info["note_id"]
    note_content = db["notes"][note_id]["content"]

    return jsonify({
        "encrypted_note": note_content,
        "server_public_key": key_info["server_public_key"]
    })

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
        if "shared_links" in db: 
            shared_links = db.get("shared_links", {})
            now = time.time()
            for token, info in shared_links.items():
                if "note_id" not in info:
                    app.logger.error(f"Token {token} không có note_id, giá trị: {info}")
                    continue  # Bỏ qua entry không hợp lệ

                note_id = info["note_id"]

            if note_id in note_tokens and now < info.get("expiry", 0):
                note_tokens[note_id].append(token)
                    
            # app.logger.info(f"Shared links data: {shared_links}")

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
