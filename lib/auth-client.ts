"use client";
import { createAuthClient } from "better-auth/react";

export const authClient = createAuthClient();
// Signing in always starts clean: a revoked or expired GitHub token kept in the old sign-in cookies would otherwise
// survive the new sign-in and keep failing with 401.
export const signInWithGitHub = async (next = "/") => { await authClient.signOut().catch(() => {}); return authClient.signIn.social({ provider: "github", callbackURL: next }); };
export const signOut = () => authClient.signOut();
