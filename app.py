import username as username
from flask import Flask, jsonify, request
from flask_restful import Api, Resource
from pymongo import Mongoclient
import bcrypt
import requests
import json
import specy

app = Flask(__name__)

api = Api(app)
client = Mongoclient("mongodb://db:27017")
db = client.similarityDB
users = db["Users"]


def UserExit(username):
    if users.find({"Username": username}).count() == 0:
        return False
    else:
        return True

    class Register(Resource):
     def post(self):
            postedData = request.get_json()
            username = postedData["username"]
            password = postedData["password"]

    if UserExit(username):
                retjson = {
                    "status": 301,
                    "msg": " Invalid Username"
                }
                return jsonify(retjson)
            hasedpw = bcrypt.hashpw(password.encode("utf8")), bcrypt.gensalt()
    users.insert(
                {
                    "username": username,
                    "password": hasedpw,
                    "Tokens": 6
                }
            )
            retjson = {
                "status": 200,
                "msg": "You successfully signup for Api"
            }
            return jsonify(retjson)

    def verify_pw(username, password, Username):
            if not UserExit(username):
                return False
            hashed_pw = users.find(
                {"username": username})[0]["password"]
            if bcrypt.hashpw(password.encode('utf8'), hashed_pw) == hashed_pw:
                return True
            else:
                return False
    def counttokens(username):
                tokens=users.find(
                    {
                        "username":username
                    })[0]["tokens"]
                return tokens

    class Detect(Resource):

            def post(self):
                postedData=request.get_json()
                username=postedData["username"]
                password=postedData["password"]
                text1=postedData["text1"]
                text2=postedData["text2"]

                if not UserExit(username):
                    retjson={
                        "status":301,
                        "msg":"Invalid Username"
                    }
                    return jsonify(retjson)
                correct_pw=verify_pw(username,password)
                if not correct_pw:
                    retjson={
                        "status":302,
                        "msg":"Invalid password"
                    }
                num_tokens=counttokens(username)

                if num_tokens <= 0:
                    retjson={
                        "status":303,
                        "msg":"you're out of tokens,please refill!"
                    }
                    return jsonify(retjson)
            #calculate the edit distance

                nlp=specy.load('en_core_web_sm')
                text1=nlp(text1)
                text2=nlp(text2)
                ratio=text1.similarity(text2)
                retjson={
                    "status":200,
                    "similarity":ratio,
                    "msg":"Similarity score calculated Successfully"
                }
currect_tokens=counttokens(username)
users.update({
    "Username":username,
             },{
    "$set":{
                     "tokents": currect_tokens-1
                 }
             })

      return jsonify(retjson)


class Refill(Resource):
        def post(self):
            postedData = request.get_json()

            username = postedData["username"]
            password = postedData["admin_pw"]
            amount = postedData["amount"]
            if not UserExit(username):
                retjson={
                    "status":301,
                    "msg": "Invalid username"
                }
                return jsonify(retjson)

            correct_pw = "abc123"
            if not password == correct_pw:
                retjson={
                    "ststus":304,
                    "msg":"Invalid Admin Password"
                }
                return jsonify(retjson)

users.update({
    "Username": username

},
    {"$set": {
        "tokents": amount
    }
    })

retjson={
    "status":200,
    "msg":"Refilled Successfully"
}

api.add_resource(Register, '/register')
api.add_resource(Detect, '/detect')
api.add_resource(Refill, '/refill')

if __name__ == '__main__':
    app.run(host='0.0.0.0')