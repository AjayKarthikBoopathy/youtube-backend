import mongoose from "mongoose";
import User from "../models/User.js";
import bcrypt from "bcryptjs";
import { createError } from "../error.js";
import jwt from "jsonwebtoken";

export const signup = async (req, res, next) => {
  try {
    const user = await User.findOne({ name: req.body.name });
    if (user) return next(createError(400, "Username already exists!"));

    const salt = bcrypt.genSaltSync(10);
    const hash = bcrypt.hashSync(req.body.password, salt);
    const newUser = new User({ ...req.body, password: hash });

    user = await newUser.save();
    console.log(user)
    //res.status(200).send("User has been created!");
    const token = jwt.sign({ id: user?._id }, process.env.JWT);
    const { password, ...others } = user?._doc;  //picked out the password

    res
      .cookie("access_token", token, {  //cookie parser installed
        httpOnly: true, //http - secure connection
        maxAge: 24 * 60 * 60 * 1000,  //1day
        sameSite: "none",
        secure: true,
      })
      .status(200).send("User has been created!")
      .json(others);
  } catch (err) {
    next(err);
  }
};

export const signin = async (req, res, next) => {
  try {
    const user = await User.findOne({ name: req.body.name });
    if (!user) return next(createError(404, "User not found!"));

    const isCorrect = await bcrypt.compare(req.body.password, user.password);

    if (!isCorrect) return next(createError(400, "Wrong Credentials!"));

    const token = jwt.sign({ id: user._id }, process.env.JWT);
    const { password, ...others } = user._doc;  //picked out the password

    res
      .cookie("access_token", token, {  //cookie parser installed
        httpOnly: true, //http - secure connection
        maxAge: 24 * 60 * 60 * 1000,
        sameSite: "none",
        secure: true,
      })
      .status(200)
      .json(others);  //omitted even the hashed password in response message
  } catch (err) {
    next(err);
  }
};

//password data is not used for signing in with Google
export const googleAuth = async (req, res, next) => {
  try {
    const user = await User.findOne({ email: req.body.email });
    if (user) {
      const token = jwt.sign({ id: user._id }, process.env.JWT);
      res
        .cookie("access_token", token, {
          httpOnly: true,
        })
        .status(200)
        .json(user._doc);
    } else {
      const newUser = new User({
        ...req.body,
        fromGoogle: true,
      });
      const savedUser = await newUser.save();
      const token = jwt.sign({ id: savedUser._id }, process.env.JWT);
      res
        .cookie("access_token", token, {
          httpOnly: true,
        })
        .status(200)
        .json(savedUser._doc);
    }
  } catch (err) {
    next(err);
  }
};
