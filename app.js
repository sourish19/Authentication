import express from "express";
import router from "./routes/user.routes.js";

const app = express();

app.use("/api/v1");

export default app;
