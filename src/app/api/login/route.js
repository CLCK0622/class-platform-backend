import { NextResponse } from "next/server";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import { pool } from "@/utils/db";

export async function POST(req) {
    const { username, password } = await req.json();

    if (!username || !password) {
        return NextResponse.json({ error: "Username and password are required" }, { status: 400 });
    }

    try {
        const user = await pool.query("SELECT * FROM users WHERE username = $1", [username]);

        if (user.rowCount === 0) {
            return NextResponse.json({ error: "Invalid username or password" }, { status: 401 });
        }

        const isValidPassword = await bcrypt.compare(password, user.rows[0].password);

        if (!isValidPassword) {
            return NextResponse.json({ error: "Invalid username or password" }, { status: 401 });
        }

        const token = jwt.sign(
            { id: user.rows[0].id, username: user.rows[0].username },
            process.env.JWT_SECRET,
            { expiresIn: "1h" }
        );

        return NextResponse.json({ token, avatar_url: user.rows[0].avatar_url });
    } catch (error) {
        return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
    }
}
