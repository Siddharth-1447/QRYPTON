import type { Metadata } from "next";
import "./globals.css";
import { ProductivityTools } from "@/components/productivity";
import { themeBootstrap } from "@/lib/theme";
import { SectionMotion } from "@/components/section-motion";

export const metadata: Metadata = {
  title: "QRYPTON | Discover. Assess. Evolve.",
  description: "Cryptographic discovery, risk assessment, and post-quantum migration planning.",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" data-theme="dark" data-resolved-theme="dark" suppressHydrationWarning className="h-full antialiased bg-background">
      <head>{["space-grotesk-latin-400-normal", "space-grotesk-latin-500-normal", "space-grotesk-latin-700-normal", "space-mono-latin-400-normal", "space-mono-latin-700-normal"].map(font => <link key={font} rel="preload" href={`/fonts/${font}.woff2`} as="font" type="font/woff2" crossOrigin="anonymous" />)}<script dangerouslySetInnerHTML={{ __html: themeBootstrap }} /></head>
      <body className="min-h-full flex flex-col">{children}<ProductivityTools /><SectionMotion /></body>
    </html>
  );
}
