from flask import Flask, request, jsonify
from models.models import User, Meal
from database import db, DateTime, datetime, timedelta
from flask_login import LoginManager, login_user, current_user, logout_user, login_required
import bcrypt

app = Flask(__name__)
app.config['SECRET_KEY'] = "your_secret_key"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///dailydiet.db'

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.checkpw(str.encode(password), user.password):
            login_user(user)
            print(current_user.is_authenticated)
            return jsonify({"message": "Autenticacao realizada com sucesso"})

    return jsonify({"message": "Credenciais invalidas"}), 400

@app.route('/logout', methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado com sucesso"})

@app.route('/user', methods=["POST"])
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if username and password:
        hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
        user = User(username=username, password=hashed_password, role='user')
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "Usuario cadastrado com sucesso"})

    return jsonify({"message": "Dados invalidos"}), 400

@app.route('/user/<int:id_user>', methods=["GET"])
@login_required
def read_user(id_user):
    user = User.query.get(id_user)

    if user:
        return {"message": user.username}

    return jsonify({"message":"Usuario não encontrado"}), 404

@app.route('/user/<int:id_user>', methods=["PUT"])
@login_required
def update_user(id_user):
    data = request.json
    user = User.query.get(id_user)

    if id_user != current_user.id and current_user.role == "user":
        return jsonify({"message": "Operação não permitida"}), 403

    if user and data.get("password"):
        new_hashed_password = bcrypt.hashpw(str.encode(data.get("password")), bcrypt.gensalt())
        user.password = new_hashed_password
        db.session.commit()

        return jsonify({"message": f"Usuario {id_user} atualizado com sucesso"})

    return jsonify({"message":"Usuario não encontrado"}), 404

@app.route('/user/<int:id_user>', methods=["DELETE"])
@login_required
def delete_user(id_user):
    user = User.query.get(id_user)

    if id_user == current_user.id and current_user.role != "admin":
        return jsonify({"message":"Deleção não permitida"}), 403

    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message": f"Usuario {id_user} deletado com sucesso"})
    
    return jsonify({"message":"Usuario não encontrado"}), 404

@app.route('/user/admin/<int:id_user>', methods=['PUT'])
@login_required
def update_user_role(id_user):
    data = request.json
    user = User.query.get(id_user)

    if current_user.role != "admin":
        return jsonify({"message": "Operação não permitida"}), 403

    if user:
        new_role = data.get("role")
        user.role = new_role
        db.session.commit()
        return jsonify({"message": f"Usuario {id_user} atualizado com sucesso"})
    
    return jsonify({"message":"Usuario não encontrado"}), 404

@app.route('/meal/add', methods=['POST'])
@login_required
def add_meal():
    user = User.query.get(int(current_user.id))
    data = request.json
    meal_name = data.get("meal_name")
    description = data.get("description")
    date_str = data.get("date_str")
    in_diet = data.get("in_diet")

    if meal_name and description and date_str:
        date = datetime.strptime(date_str, '%d-%m-%Y %H:%M:%S')
        meal = Meal(meal_name=meal_name, description=description, date=date, in_diet=in_diet,user_id=user.id)
        db.session.add(meal)
        db.session.commit()
        return jsonify({"message": "Refeição adicionada com sucesso!"})

    return jsonify({"message": "Dados inválidos"}), 400

@app.route('/meal/read', methods=['GET'])
@login_required
def read_meals():
    user = User.query.get(int(current_user.id))
    meals = user.meals
    user_meals = []
    if meals:
        for meal in meals:
            meals_user = Meal.query.get(meal.user_id)
            user_meals.append   ({
                                "meal_name": meal.meal_name,
                                "description": meal.description,
                                "date": meal.date,
                                "in_diet": meal.in_diet,
                                "id": meal.id
                                })
        return jsonify(user_meals)

    return jsonify({"message": "Nenhuma refeicao cadastrada"}), 400

@app.route('/meal/<int:id_meal>', methods=['GET'])
@login_required
def read_espf_meal(id_meal):
    user = User.query.get(int(current_user.id))
    meals = user.meals
    meal = Meal.query.get(id_meal)

    if meal.user_id != current_user.id:
        return jsonify({"message": "Operacao nao permitida"}), 403

    if meal:
        return jsonify({
                        "meal_name": meal.meal_name,
                        "description": meal.description,
                        "date": meal.date,
                        "in_diet": meal.in_diet,
                        })
    return jsonify({"message": "Refeicao nao encontrada"}), 404

@app.route('/meal/delete/<int:id_meal>', methods=['DELETE'])
@login_required
def delete_meal(id_meal):
    user = User.query.get(int(current_user.id))
    meals = user.meals
    meal = Meal.query.get(id_meal)

    if current_user.id == meal.user_id:
        if meal:
            db.session.delete(meal)
            db.session.commit()
            return jsonify({"message": f"Refeicao {id_meal} deletada com sucesso"})
        return jsonify({"message": "Refeicao nao encontrada"}), 404
    return jsonify({"message": "Operacao nao permitida"}), 403


@app.route('/meal/update/<int:id_meal>', methods=['PUT'])
@login_required
def update_meal(id_meal):
    data = request.json
    user = User.query.get(int(current_user.id))
    meal = Meal.query.get(id_meal)
   
    if current_user.id != meal.user_id:
        return jsonify({"message": "Operacao nao permitida"}), 403

    new_date_str = data.get("new_date_str")
    if new_date_str:
        new_date = datetime.strptime(new_date_str, '%d-%m-%Y %H:%M:%S')
        meal.date = new_date
        pass
   
    new_description = data.get("new_description")
    if new_description:
        meal.description = new_description
        pass
    
    new_name = data.get("new_name")
    if new_name:
        meal.meal_name = new_name
        pass

    new_in_diet = data.get("new_in_diet")
    if new_in_diet != meal.in_diet:
        meal.in_diet = new_in_diet
        pass
    
    if meal:
        db.session.commit()
        return jsonify({"message": f"Refeicao {id_meal} atualizada com sucesso"})
    return jsonify({"message": "Refeicao nao encontrada"}), 404


if __name__ == '__main__':
    app.run(debug=True)