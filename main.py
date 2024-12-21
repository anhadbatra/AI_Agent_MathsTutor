from flask import request, jsonify
from langchain.chat_models import ChatOpenAI
from langchain.prompts.chat import (
    ChatPromptTemplate,
    SystemMessagePromptTemplate,
    HumanMessagePromptTemplate,
)
import requests
from config import app,limiter
import sqlite3
import bcrypt
import os
from dotenv import load_dotenv
import re

# Initialize Flask app
load_dotenv()
def create_database():
    conn = sqlite3.connect('todo.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT,password TEXT)''')
    conn.commit()
    conn.close()

openai_api_key = os.environ.get("OPENAI_API_KEY")
TAVILY_API_KEY = os.environ.get("TAVILY_API_KEY")
TAVILY_BASE_URL = "https://api.tavily.com"
chat = ChatOpenAI(model="gpt-4", temperature=0.2, openai_api_key=openai_api_key)

system_message = SystemMessagePromptTemplate.from_template(
    "You are a helpful and knowledgeable AI math tutor. You solve math problems and explain each step in detail."
)
human_message = HumanMessagePromptTemplate.from_template("{query}")
prompt = ChatPromptTemplate.from_messages([system_message, human_message])

def tavily_search(input_data):
    endpoint = f"{TAVILY_BASE_URL}/search"
    headers = {"Authorization": f"Bearer {TAVILY_API_KEY}"}

    payload = {
        "api_key": TAVILY_API_KEY,
        "query": input_data.get("query", ""),
        "search_depth": input_data.get("search_depth", "basic"),
        "include_answer": input_data.get("include_answer", False),
        "include_images": input_data.get("include_images", False),
        "include_image_descriptions": input_data.get("include_image_descriptions", False),
        "include_raw_content": input_data.get("include_raw_content", False),
        "max_results": input_data.get("max_results", 5),
        "include_domains": input_data.get("include_domains", []),
        "exclude_domains": input_data.get("exclude_domains", [])
    }

    response = requests.post(endpoint, headers=headers, json=payload)


    if response.status_code == 200:
        return response.json()  
    else:
        return {
            "error": response.json().get("message", "Failed to retrieve search results"),
            "status_code": response.status_code,
            "details": response.text
        }

def solve_math_problem(query):
    try:
        messages = prompt.format_prompt(query=query).to_messages()
        response = chat(messages)
        return response.content
    except Exception as e:
        return f"Error: {e}"

@limiter.limit("5 per minute") 
@app.route('/api/solve', methods=['POST'])
def solve():
    data = request.json
    query = data.get('query', '')
    username = data.get('username')
    password = data.get('password')
    if not username and password:
        return jsonify({"error":"Username and password are required"}),400
    conn = sqlite3.connect('todo.db')
    c = conn.cursor()
    c.execute('SELECT password FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    conn.close()
    if not result:
        return jsonify({"error": "Invalid username or password"}), 401 
    stored_password = result[0]
    if not bcrypt.checkpw(password.encode('utf-8'), stored_password):
        return jsonify({"error": "Invalid password"}), 401
    if not query:
        return jsonify({"error": "No query provided"}), 400
    result = solve_math_problem(query)
    return jsonify({"query": query, "result": result})

@limiter.limit("5 per minute") 
@app.route('/api/generate_quiz', methods=['POST'])
def generate_quiz():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username and password:
        return jsonify({"error":"Username and password are required"}),400
    conn = sqlite3.connect('todo.db')
    c = conn.cursor()
    c.execute('SELECT password FROM users WHERE username = ?', (username,))
    result = c.fetchone()
    conn.close()
    if not result:
        return jsonify({"error": "Invalid username or password"}), 401 
    stored_password = result[0]
    if not bcrypt.checkpw(password.encode('utf-8'), stored_password):
        return jsonify({"error": "Invalid password"}), 401
    result = tavily_search(data)
    return jsonify(result)

@app.route("/api/register",methods=['POST'])
@limiter.limit("5 per minute")
def register():
    try:
        data = request.json
        username = data.get('username')
        password = data.get('password')
        if not username or not password:
            return jsonify({"error": "Username and password are required"}), 400
        if not re.match(r"^[a-zA-Z0-9_]{3,20}$", username):
            return jsonify({"error": "Username must be 3-20 characters long and contain only letters, numbers, and underscores"}), 400
        encrypt_password = bcrypt.hashpw(password.encode('utf-8'),bcrypt.gensalt())
        conn = sqlite3.connect('todo.db')
        c = conn.cursor()
        c.execute('INSERT INTO users(username,password) VALUES (?,?)',(username,encrypt_password))
        conn.commit()
        conn.close()
        return jsonify({"message":"User registered sucessfully"}),201
    except sqlite3.IntegrityError:
        return jsonify({"error": "Username already exists"}), 409
    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == '__main__':
    create_database()
    app.run(debug=True)
