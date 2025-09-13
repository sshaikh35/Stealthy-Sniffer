from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def form():
    return '''
    <form method="post" action="/login">
      <input name="username" placeholder="Username"><br>
      <input name="password" placeholder="Password" type="password"><br>
      <input type="submit">
    </form>
    '''

@app.route('/login', methods=['POST'])
def login():
    u = request.form.get('username')
    p = request.form.get('password')
    print(f"[+] Received login: {u}:{p}")
    return "Login received (check your sniffer!)"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
