import UserModel from "../models/User.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

class UserController {
  static userRegistration = async (req, res) => {
    const { name, email, password, password_confirmation, tc } = req.body;
    const user = await UserModel.findOne({ email: email });

    if (user) {
      res.send({ status: "failed", message: "Email already exists" });
    } else {
      if (name && email && password && password_confirmation && tc) {
        if (password === password_confirmation) {
          try {
            const hashPassword = await bcrypt.hash(password, 10);
            const doc = new UserModel({
              name: name,
              email: email,
              password: hashPassword,
              tc: tc,
            });
            await doc.save();
            const saved_user = await UserModel.findOne({ email: email });
            //Generate JWT Token
            const token = jwt.sign({ userID: saved_user._id });

            res.status(201).send({
              status: "success",
              message: "registration Success",
            });
          } catch (error) {
            console.log(error);
            res.send({
              status: "failed",
              message: "unable to registrate",
            });
          }
        } else {
          res.send({
            status: "failed",
            message: "password and confirm password doesn't match",
          });
        }
      } else {
        res.send({ status: "failed", message: "All fields are required" });
      }
    }
  };

  //login
  static userLogin = async (req, res) => {
    try {
      const { email, password } = req.body;
      if (email && password) {
        const user = await UserModel.findOne({ email: email });
        if (user != null) {
          const isMatch = await bcrypt.compare(password, user.password);
          if (user.email === email && isMatch) {
            res.send({
              status: "success",
              message: "Login Success",
            });
          } else {
            res.send({
              status: "failed",
              message: "Email or Password is not Valid",
            });
          }
        } else {
          res.send({
            status: "failed",
            message: "you are not registered User",
          });
        }
      } else {
        res.send({
          status: "failed",
          message: "All fields are required  for login",
        });
      }
    } catch (error) {
      console.log(error);
      res.send({
        status: "failed",
        message: "unable to Login",
      });
    }
  };
}

export default UserController;
