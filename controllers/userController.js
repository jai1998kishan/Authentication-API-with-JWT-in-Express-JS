import UserModel from "../models/User.js";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";

class UserController {
  //registration
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
            const token = jwt.sign(
              { userID: saved_user._id },
              process.env.JWT_SECRET_KEY,
              { expiresIn: "5d" }
            );

            res.status(201).send({
              status: "success",
              message: "registration Success",
              token: token,
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
            //Generate JWT Token
            const token = jwt.sign(
              { userID: user._id },
              process.env.JWT_SECRET_KEY,
              { expiresIn: "5d" }
            );

            res.send({
              status: "success",
              message: "Login Success",
              token: token,
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

  //changing password
  static changeUserPassword = async (req, res) => {
    const { password, password_confirmation } = req.body;
    if (password && password_confirmation) {
      if (password !== password_confirmation) {
        res.send({
          status: "failed",
          message: "New password and confirm password doesn't match..",
        });
      } else {
        const newHashPassword = await bcrypt.hash(password, 10);
        // console.log(req.user);
        // console.log(req.user._id);
        await UserModel.findByIdAndUpdate(req.user._id, {
          $set: { password: newHashPassword },
        });
        res.send({
          status: "success",
          message: "Password change successfully",
        });
      }
    } else {
      res.send({
        status: "failed",
        message: "All fields are required",
      });
    }
  };
}

export default UserController;
