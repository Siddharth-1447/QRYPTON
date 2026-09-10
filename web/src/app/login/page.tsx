"use client";

import { useRouter } from "next/navigation";
import { AuthFlow } from "@/components/auth-flow";

export default function LoginPage() {
  const router = useRouter();
  return <AuthFlow onComplete={() => router.replace("/")} />;
}
