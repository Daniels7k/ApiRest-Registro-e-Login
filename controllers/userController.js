const User = require("../models/User")
const bcrypt = require("bcryptjs")
const jwt = require("jsonwebtoken")

const {loginValidate, registerValidate} = require ("./validate")


const userController = {
    register: async function (req, res) {

        //Validação pré banco de dados
        const {error} = registerValidate(req.body)
        if(error){return res.status(400).send(error.message)}


        //Verificando a pre-existência de email no banco de dados
        const selectedUser = await User.findOne({ email: req.body.email })
        if (selectedUser) return res.status(400).send("email already exist")

        //Registrando o usuário no banco de dados
        const user = new User({
            name: req.body.name,
            email: req.body.email,
            password: bcrypt.hashSync(req.body.password)
        })
        try {
            const savedUser = await user.save()
            res.send(savedUser)
        } catch (error) {
            res.status(400).send(error)
        }

    },

    login: async function (req, res) {

        //Validação pré banco de dados
        const {error} = loginValidate(req.body)
        if(error){return res.status(400).send(error.message)}
        
        //Verificando a pre-existência de email no banco de dados
        const selectedUser = await User.findOne({ email: req.body.email })
        if (!selectedUser) return res.status(400).send("email or password incorrect")

        //Comparando o password com o hash do banco de dados
        const passwordAndUserMatch = bcrypt.compareSync(req.body.password, selectedUser.password)
        if (!passwordAndUserMatch) return res.status(400).send("email or password incorrect")

        //Criando o Token do JWT
        const token = jwt.sign({id:selectedUser.id, admin: selectedUser.admin}, process.env.TOKEN_SECRET)

        res.header("authorization-token", token)

        res.send("User Logged")
    }
}


module.exports = userController