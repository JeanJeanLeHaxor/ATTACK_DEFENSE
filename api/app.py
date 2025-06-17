from flask import Flask, request, jsonify
from flasgger import Swagger
from pymongo import MongoClient

app = Flask(__name__)
swagger = Swagger(app)

# MongoDB connection (use service name from docker-compose)
client = MongoClient("mongodb://mongo:27017/")
db = client["vulnlab"]
users_collection = db["users"]

# Insert test users once
if users_collection.count_documents({}) == 0:
    users_collection.insert_many([
        {"username": "admin", "password": "supersecret"},
        {"username": "user1", "password": "password123"}
    ])

@app.route('/login', methods=['POST'])
def login():
    """
    Login endpoint vulnerable to NoSQL Injection
    ---
    tags:
      - Authentication
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            username:
              type: string
            password:
              type: string
    responses:
      200:
        description: Successful login
      401:
        description: Unauthorized
    """
    data = request.get_json()
    username = data.get("username")
    password = data.get("password")

    user = users_collection.find_one({"username": username, "password": password})
    if user:
        return jsonify({"message": "Login successful", "user": user["username"]})
    return jsonify({"message": "Invalid credentials"}), 401

@app.route('/swagger.json')
def swagger_spec():
    return jsonify(swagger.get_apispecs())

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
