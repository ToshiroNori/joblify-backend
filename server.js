import express from "express";
import dotenv from "dotenv";
import cookieParser from "cookie-parser";
import cors from "cors";
import mongoose from "mongoose";
import userModel from "./model/User.js";
import jwt from "jsonwebtoken";
import bcrypt from "bcryptjs";
import { protectedRoute } from "./middleware/protected.js";
import { transporter } from "./middleware/nodemailer.js";
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
    if (user.password !== password) {
      return res.status(400).json({ message: "Invalid email or password" });
    }
    const token = jwt.sign(
      { id: user._id, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: "1d" }
    );
    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "strict",
      maxAge: 1000 * 60 * 60 * 24,
    });

    return res.status(200).json({
      message: "Login successful",
      user: {
        name: user.name,
        contact: user.contact,
        email: user.email,
        role: user.role,
        company: user.company ? user.company : null,
        company_size: user.company_size ? user.company_size : null,
      },
    });
  } catch (error) {
    return res.status(500).json({ message: error.message });
  }
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
  const { name, contact, email, company, company_size, password, role } =
    req.body;
  if (!name || !contact || !email || !password || !role) {
    return res.status(400).json({ message: "Please fill all the fields" });
  }
  try {
    const alreadyExists = await userModel.findOne({ email: email });
    if (alreadyExists) {
      return res.status(400).json({ message: "User already exists" });
    }
    const contactExists = await userModel.findOne({ contact: contact });
    if (contactExists) {
      return res.status(400).json({ message: "Contact already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 10);
    const user = await userModel.create({
      name,
      contact,
      email,
      company,
      company_size,
      password: hashedPassword,
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
      html: `<h1>Welcome ${user.name}</h1><p>You have registered successfully</p>`,
    };
    await transporter.sendMail(emailOption);
    return res.status(201).json({
      message: "User created successfully",
      user: {
        name: user.name,
        contact: user.contact,
        email: user.email,
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
