import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

export const protectedRoute = (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.status(401).json({ message: "Unauthorized" });
  }
  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ message: "Forbidden" });
    }
    req.user = decoded;
    next();
  });
};
