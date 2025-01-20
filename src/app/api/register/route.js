import { NextResponse } from "next/server";
import bcrypt from "bcrypt";
import { pool } from "@/utils/db";

export async function POST(req) {
    const { username, email, password } = await req.json();

    if (!username || !email || !password) {
        return NextResponse.json({ error: "All fields are required" }, { status: 400 });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        await pool.query(
            "INSERT INTO users (username, email, password) VALUES ($1, $2, $3)",
            [username, email, hashedPassword]
        );

        return NextResponse.json({ message: "User registered successfully" }, { status: 201 });
    } catch (error) {
        if (error.code === "23505") {
            return NextResponse.json({ error: "Username or email already exists" }, { status: 400 });
        } else {
            return NextResponse.json({ error: "Internal Server Error" }, { status: 500 });
        }
    }
}
