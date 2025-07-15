from flask import Flask, render_template, request, redirect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime



app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///todo.db'
db = SQLAlchemy(app)

class Todo(db.Model):
    Sno = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.String(100), nullable=False)
    date_creates = db.Column(db.DateTime, default=datetime.utcnow)

    def __repr__(self) -> str:
        return f"{self.Sno} - {self.title}"


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['desc']
        
        todo = Todo(title = title, description = description)
        db.session.add(todo)
        db.session.commit()
    allTodo = Todo.query.all()
    return render_template('index.html', allTodo=allTodo)

@app.route('/about')
def about():
    allTodo = Todo.query.all()
    return render_template('about.html', allTodo=allTodo)


@app.route('/update/<int:Sno>', methods=['GET', 'POST'])
def update(Sno):
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['desc']
        todo = Todo.query.filter_by(Sno = Sno).first()
        todo.title = title
        todo.description = description
        db.session.add(todo)
        db.session.commit()
        return redirect('/')

    todo = Todo.query.filter_by(Sno = Sno).first()
    return render_template('update.html', todo = todo)

@app.route('/delete/<int:Sno>')
def delete(Sno):
    todo = Todo.query.filter_by(Sno = Sno).first()
    db.session.delete(todo)
    db.session.commit()
    return redirect('/')



if __name__ == '__main__':
    app.run(debug=True, port = 8000)