import * as React from "react"
import { cva, type VariantProps } from "class-variance-authority"
import {
  Copy,
  Eye,
  EyeOff,
  KeyRound,
  MoreHorizontal,
  RotateCw,
} from "lucide-react"

import { cn } from "@/lib/utils"
import { Badge } from "@/components/ui/badge"
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu"

const secretCardVariants = cva(
  "group relative flex flex-col justify-between rounded-lg border border-border bg-card p-4 text-card-foreground shadow-[var(--shadow-card)] transition-all duration-150 hover:border-border-strong",
  {
    variants: {
      variant: {
        default: "gap-3",
        compact: "gap-2 p-3",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  }
)

export interface SecretCardProps
  extends React.ComponentProps<"div">,
    VariantProps<typeof secretCardVariants> {
  secretKey: string
  secretValue: string
  path?: string
  updatedAt?: string
  version?: number
  rotation?: string
  actor?: string
  onRotate?: (key: string) => void
  onViewHistory?: (key: string) => void
  onCopy?: (key: string) => void
}

function SecretCard({
  className,
  variant,
  secretKey,
  secretValue,
  path = "/",
  updatedAt,
  version = 1,
  rotation,
  actor,
  onRotate,
  onViewHistory,
  onCopy,
  ...props
}: SecretCardProps) {
  const [isRevealed, setIsRevealed] = React.useState(false)

  const handleCopy = async () => {
    await navigator.clipboard?.writeText(secretValue)
    onCopy?.(secretKey)
  }

  const toggleReveal = () => {
    setIsRevealed((prev) => !prev)
  }

  return (
    <div
      data-slot="secret-card"
      data-variant={variant}
      className={cn(secretCardVariants({ variant, className }))}
      {...props}
    >
      {/* Card Header */}
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <div
            className="flex size-7 shrink-0 items-center justify-center rounded-md border border-border bg-muted text-muted-foreground"
            aria-hidden="true"
          >
            <KeyRound className="size-3.5" />
          </div>
          <div className="flex flex-col min-w-0">
            <span className="truncate font-mono text-xs font-semibold text-foreground">
              {secretKey}
            </span>
            <span className="truncate font-mono text-[11px] text-muted-foreground">
              {path}
            </span>
          </div>
        </div>

        <div className="flex items-center gap-1.5 shrink-0">
          {rotation && (
            <Badge
              variant="outline"
              className="gap-1 text-[10px] font-normal"
              title={`Rotates every ${rotation}`}
            >
              <RotateCw className="size-2.5 text-muted-foreground" aria-hidden="true" />
              <span>{rotation}</span>
            </Badge>
          )}
          <Badge variant="secondary" className="text-[10px] font-normal">
            v{version}
          </Badge>
        </div>
      </div>

      {/* Secret Payload Masked Display */}
      <div className="flex items-center justify-between rounded-md border border-border bg-muted/50 px-2.5 py-1.5 font-mono text-xs text-muted-foreground">
        <code className="truncate">
          {isRevealed ? secretValue : "••••••••••••••••••••"}
        </code>
        <div className="flex items-center gap-1 ms-2 shrink-0">
          <button
            type="button"
            onClick={toggleReveal}
            aria-label={
              isRevealed
                ? `Hide ${secretKey} value`
                : `Reveal ${secretKey} value`
            }
            aria-pressed={isRevealed}
            title={isRevealed ? "Hide value" : "Reveal value"}
            className="inline-flex size-7 items-center justify-center rounded text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring"
          >
            {isRevealed ? (
              <EyeOff className="size-3.5" aria-hidden="true" />
            ) : (
              <Eye className="size-3.5" aria-hidden="true" />
            )}
          </button>
          <button
            type="button"
            onClick={handleCopy}
            aria-label={`Copy ${secretKey} to clipboard`}
            title="Copy secret"
            className="inline-flex size-7 items-center justify-center rounded text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring"
          >
            <Copy className="size-3.5" aria-hidden="true" />
          </button>
        </div>
      </div>

      {/* Card Footer */}
      <div className="flex items-center justify-between pt-1 text-[11px] text-muted-foreground border-t border-border/50">
        <span className="truncate">
          {updatedAt ? `Updated ${updatedAt}` : "Active"}
          {actor && ` by ${actor}`}
        </span>

        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <button
              type="button"
              aria-label={`More actions for ${secretKey}`}
              className="inline-flex size-6 items-center justify-center rounded text-muted-foreground hover:bg-muted hover:text-foreground focus-visible:ring-2 focus-visible:ring-ring"
            >
              <MoreHorizontal className="size-3.5" aria-hidden="true" />
            </button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={() => onViewHistory?.(secretKey)}>
              Version history
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => onRotate?.(secretKey)}>
              Rotate secret now
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>
    </div>
  )
}

export { SecretCard, secretCardVariants }
