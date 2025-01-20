import { NextResponse } from "next/server";
import jwt from "jsonwebtoken";

export async function GET(req) {
    const token = req.headers.get("authorization")?.split(" ")[1];

    if (!token) {
        return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        return NextResponse.json({ user: decoded });
    } catch {
        return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }
}
