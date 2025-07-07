import { Router } from "express";

const router = Router();

router.route("/user").get((req, res) => {
  res.status(200).json({ status: "ok" });
});

export default router;
