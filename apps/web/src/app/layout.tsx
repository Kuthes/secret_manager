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
      <body className="antialiased">
        <a
          href="#main-content"
          className="sr-only focus:not-sr-only focus:fixed focus:top-3 focus:left-3 focus:z-50 focus:px-4 focus:py-2 focus:bg-primary focus:text-primary-foreground focus:rounded-md focus:shadow-md focus:outline-none focus:ring-2 focus:ring-ring"
        >
          Skip to main content
        </a>
        {children}
      </body>
    </html>
  );
}
