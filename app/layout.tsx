import type { Metadata } from "next";
import "./globals.css";

export const metadata: Metadata = {
  title: "AegisVault Security Platform",
  description: "Self-hosted secrets, PKI, KMS, access and audit security control plane.",
  other: {
    "codex-preview": "development",
  },
  icons: {
    icon: "/favicon.svg",
    shortcut: "/favicon.svg",
  },
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en">
      <body className="antialiased">{children}</body>
    </html>
  );
}
