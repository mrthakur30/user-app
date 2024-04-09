import NextAuth from "next-auth/next";
import  CredentialsProvider from "next-auth/providers/credentials";
import prisma from "../../../../../prisma/db";
import bcrypt from "bcrypt";

const handler = NextAuth({
     providers: [
      CredentialsProvider({
          name: 'Credentials',
          credentials: {
            phone: { label: "Phone number", type: "text", placeholder: "1231231231", required: true },
            password: { label: "Password", type: "password", required: true }
          },
          
          async authorize(credentials: any) {
            
            const hashedPassword = await bcrypt.hash(credentials.password, 10);
            const existingUser = await prisma.user.findFirst({
                where: {                                                                
                    number: credentials.phone
                }
            });

            if (existingUser) {
                const passwordValidation = await bcrypt.compare(credentials.password, existingUser.password);
                if (passwordValidation) {
                    return {
                        id: existingUser.id.toString(),
                        name: existingUser.name,
                        email: existingUser.number
                    }
                }
                return null;
            }

            try {
                const user = await prisma.user.create({
                    data: {
                        number: credentials.phone,
                        password: hashedPassword
                    }
                });
            
                return {
                    id: user.id.toString(),
                    name: user.name,
                    email: user.number
                }
            } catch(e) {
                console.error(e);
            }

            return null
          },
        })
    ],
});

export const GET = handler;
export const POST = handler;