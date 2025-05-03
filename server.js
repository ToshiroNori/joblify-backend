import express from "express";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import cors from "cors";
import mongoose from "mongoose";
import userModel from "./model/User.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { protectedRoute } from "./middleware/protected.js";
import {
  transporter,
  emailTemplate,
  generateOTP,
} from "./mailer/nodemailer.js";
dotenv.config();

const app = express();
app.use(
  cors({
    origin: "http://localhost:5173",
    credentials: true,
  })
);
app.use(express.json());
app.use(cookieParser());

app.get("/authcheck", protectedRoute, async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ message: "Unauthorized" });
    }
    const user = await userModel.findById(req.user.id);
    if (!user) {
      return res.status(401).json({ message: "Unauthorized" });
    }

    return res.status(200).json({
      message: "User authenticated",
      user: {
        name: user.name,
        contact: user.contact,
        email: user.email,
        role: user.role,
        isActivated: user.isActivated,
        company: user.company ? user.company : null,
        company_size: user.company_size ? user.company_size : null,
      },
    });
  } catch (error) {
    return res.status(401).json({ message: "Unauthorized" });
  }
});

app.post("/login", async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "Please fill all the fields" });
  }
  try {
    const user = await userModel.findOne({ email: email });
    if (!user) {
      return res.status(400).json({ message: "User not found" });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }
    const token = jwt.sign(
      { id: user._id, name: user.name, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "None" : "Strict",
      maxAge: 1000 * 60 * 60 * 24,
    });

    return res.status(200).json({
      message: "Login successful",
      user: {
        name: user.name,
        contact: user.contact,
        email: user.email,
        role: user.role,
        isActivated: user.isActivated,
        company: user.company ? user.company : null,
        company_size: user.company_size ? user.company_size : null,
      },
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

app.get("/logout", (req, res) => {
  res.clearCookie("token", {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: process.env.NODE_ENV === "production" ? "None" : "Strict",
  });
  return res.status(200).json({ message: "Logout successful" });
});

app.get("/users", protectedRoute, async (req, res) => {
  try {
    // if (req.user.role !== "admin") {
    //   return res.status(403).json({ message: "Forbidden" });
    // }
    const users = await userModel.find();
    if (!users || users.length === 0) {
      return res.status(404).json({ message: "No users found" });
    }
    return res.status(200).json(users);
  } catch (error) {
    console.error("Error fetching users:", error);
    res.status(500).json({ error: "Internal server error" });
  }
});

app.post("/register", async (req, res) => {
  const {
    name,
    contact,
    email,
    company,
    company_size,
    password,
    confirmPassword,
    role,
    location,
  } = req.body;
  if (
    !name ||
    !contact ||
    !email ||
    !password ||
    !confirmPassword ||
    !role ||
    !location
  ) {
    return res.status(400).json({ message: "Please fill all the fields" });
  }
  try {
    const alreadyExists = await userModel.findOne({ email: email });
    if (alreadyExists) {
      return res.status(400).json({ message: "User already exists" });
    }
    if (password !== confirmPassword) {
      return res.status(400).json({ message: "Passwords do not match" });
    }
    const contactExists = await userModel.findOne({ contact: contact });
    if (contactExists) {
      return res.status(400).json({ message: "Contact already exists" });
    }
    const OTP = generateOTP();
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await userModel.create({
      name,
      contact,
      location,
      email,
      company,
      company_size,
      password: hashedPassword,
      OTP: OTP,
      OTP_expiry: Date.now() + 10 * 60 * 60 * 24 * 3, // 3 days
      role,
    });
    if (!user) {
      return res.status(500).json({ message: "User creation failed" });
    }
    const emailOption = {
      from: `"Daddy's Solution" <${process.env.SMTP_SENDER}>`,
      subject: "Register successful",
      to: user.email,
      text: "You have registered successfully",
      html: emailTemplate(user.name, OTP, 3),
    };
    await transporter.sendMail(emailOption);
    return res.status(201).json({
      message: "User created successfully",
      user: {
        name: user.name,
        contact: user.contact,
        email: user.email,
        location: user.location,
        role: user.role,
        company: user.company ? user.company : null,
        company_size: user.company_size ? user.company_size : null,
      },
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

mongoose
  .connect(process.env.MONGO_URI)
  .then(() => {
    console.log("MongoDB connected successfully");
  })
  .catch((error) => {
    console.error("MongoDB connection error:", error);
  });
