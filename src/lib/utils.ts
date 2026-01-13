import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";
import DOMPurify from "dompurify";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

// Strip markdown-style links [text](url) to just text and remove citations/sources
export function stripMarkdownLinks(text: string): string {
  if (!text) return text;
  return text
    .replace(/\[([^\]]+)\]\([^)]+\)/g, "$1")
    .replace(/\(Citation:\s*[^)]+\)/gi, "")
    .replace(/'Source:\s*/gi, "");
}

// Sanitize and strip markdown links - use this for dangerouslySetInnerHTML
export function sanitizeHtml(text: string): string {
  if (!text) return text;
  const stripped = stripMarkdownLinks(text);
  return DOMPurify.sanitize(stripped, {
    ALLOWED_TAGS: ["b", "i", "em", "strong", "br", "p", "ul", "ol", "li", "a", "code", "pre"],
    ALLOWED_ATTR: ["href", "target", "rel"],
  });
}

export const extractIndicatorType = (pattern: string | null, observableType: string | null): string => {
  if (observableType && !["StixFile", "File"].includes(observableType)) {
    return observableType;
  }
  if (!pattern) return observableType || "Unknown";

  const hashMatch = pattern.match(/file:hashes\.['"]?([\w-]+)['"]?/i);
  if (hashMatch) return hashMatch[1].toUpperCase();

  const typeMatch = pattern.match(/\[([a-z0-9-]+):/i);
  if (typeMatch) {
    const typeMap: Record<string, string> = {
      hostname: "Hostname",
      "ipv4-addr": "IPv4",
      "ipv6-addr": "IPv6",
      "domain-name": "Domain",
      url: "URL",
      "email-addr": "Email",
      file: "File",
      "mac-addr": "MAC",
      "windows-registry-key": "Registry",
      "user-account": "User Account",
      process: "Process",
    };
    return typeMap[typeMatch[1].toLowerCase()] || typeMatch[1];
  }
  return observableType || "Unknown";
};

export const getIndicatorTypeColor = (type: string): string => {
  const colors: Record<string, string> = {
    Hostname: "bg-blue-500/10 text-blue-500 border-blue-500/20",
    IPv4: "bg-green-500/10 text-green-500 border-green-500/20",
    "IPv4-Addr": "bg-green-500/10 text-green-500 border-green-500/20",
    IPv6: "bg-green-500/10 text-green-500 border-green-500/20",
    "IPv6-Addr": "bg-green-500/10 text-green-500 border-green-500/20",
    Domain: "bg-purple-500/10 text-purple-500 border-purple-500/20",
    "Domain-Name": "bg-purple-500/10 text-purple-500 border-purple-500/20",
    URL: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
    Url: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
    Email: "bg-pink-500/10 text-pink-500 border-pink-500/20",
    "Email-Addr": "bg-pink-500/10 text-pink-500 border-pink-500/20",
    "SHA-256": "bg-orange-500/10 text-orange-500 border-orange-500/20",
    "SHA-1": "bg-orange-500/10 text-orange-500 border-orange-500/20",
    MD5: "bg-red-500/10 text-red-500 border-red-500/20",
    File: "bg-orange-500/10 text-orange-500 border-orange-500/20",
    StixFile: "bg-orange-500/10 text-orange-500 border-orange-500/20",
    Registry: "bg-slate-500/10 text-slate-500 border-slate-500/20",
    MAC: "bg-cyan-500/10 text-cyan-500 border-cyan-500/20",
  };
  return colors[type] || "bg-muted text-muted-foreground";
};
