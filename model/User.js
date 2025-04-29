import mongoose from "mongoose";

const userSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
    trim: true,
    minLength: 2,
    maxLength: 50,
  },
  contact: {
    type: String,
    required: [true, "Contact number is required"],
    unique: [true, "Contact number already exists"],
    minLength: [10, "Contact number must be at least 10 digits"],
    maxLength: [10, "Contact number must be at most 10 digits"],
  },
  email: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    lowercase: true,
  },
  company: {
    type: String,
    required: function () {
      return this.role === "employer";
    },
    trim: true,
    minLength: 2,
    maxLength: 50,
  },
  company_size: {
    type: String,
    required: function () {
      return this.role === "employer";
    },
    enum: ["1-10", "11-50", "51-200", "201-500", "501"],
    default: function () {
      return this.role === "employer" ? "1-10" : undefined;
    },
  },
  password: {
    type: String,
    required: true,
    minLength: 8,
  },
  OTP: {
    type: String,
    default: null,
  },
  OTP_expiry: {
    type: Date,
    default: null,
  },
  isActivated: {
    type: Boolean,
    default: false,
  },
  role: {
    type: String,
    required: true,
    enum: ["admin", "candidate", "employer"],
    default: "candidate",
  },
});

const userModel = mongoose.model("userModel", userSchema);
export default userModel;
